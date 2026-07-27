"""The shadow-confirmation WRITER — PLAN.md §2 invariant 7 (Tier B quarantine), §5 row 4.

`memory_item.shadow_confirm_runs` is the only non-human route out of `quarantined`
(`domain.state_machine._guard_quarantined_to_candidate`), and until this module existed
nothing wrote it: `docs/FIDELITY-AUDIT.md` M6, PLAN.md §11.1 — "nothing appends
`shadow_confirm_runs`"; `workers/shadow_validator.py`'s own docstring said the
`confirming_run_ids` projection it consumes has no producer. This module is that producer.

Scope boundary, deliberately: deciding WHICH runs are worth OFFERING as a candidate
confirmation for WHICH quarantined memory — matching a re-derived lesson's `content_hash`
against an existing quarantined row, a webhook tying a later outcome back to a specific
`memory_id`, an operator's manual flag — is not this chunk's job. That is exactly the same
shape of boundary `workers.shadow_validator.QuarantinedMemoryRow` already draws around
`confirming_run_ids` ("reading the store row shape is outside this chunk") and the shape
`workers.revalidation.RevalidationCheckPort` already draws around "what counts as
re-verified" (host-supplied, not that worker's invention). `CorroborationCandidateSource`
below is the same kind of seam: whoever wires this worker into the batch plane supplies it.

What this module DOES own, and is the entire reason it exists — turning one OFFERED
`(memory, run_id)` pair into a SAFE, auditable append to `shadow_confirm_runs`:

  1. quarantined rows only, in the caller's own project (`_require_row`, the same defensive
     re-assertion every sibling lifecycle worker — `shadow_validator`, `revalidation`,
     `sweeps` — applies to its own select's output, because a select that over-returns is a
     bulk mis-transition waiting to happen and the predicate that stops it lives in a store
     this chunk does not own). `run_once` applies it to EVERY row before the host-supplied
     `CorroborationCandidateSource` is consulted for any of them: the source is third-party
     code, so handing it a row from another project would be an invariant-4 disclosure even
     if nothing were ever written for that row;
  2. a memory can never corroborate itself. `origin_runs` is IMPORTED from
     `workers.shadow_validator`, not reimplemented — D-118's postmortem is exactly the
     failure mode of a second author for one governing definition, and PLAN.md's own task
     description for this chunk names the same hazard for independence. There is exactly
     one definition of "a memory's own origin runs" in this codebase, and this module reuses
     it rather than growing a second one that could silently drift;
  3. idempotent, concurrency-safe recording — see `CorroborationRepoPort
     .append_confirming_run`'s docstring for the exact choice and why;
  4. a bounded array. PLAN.md §5 calls `shadow_confirm_runs` "distinct confirming run_ids
     (distinctness is checkable)"; distinctness and boundedness are properties of the COLUMN,
     so they hold per row across a whole batch, not per call (see `run_once`);
  5. NO independence judgement. `workers.independence` / `domain.state_machine` decide
     whether a recorded run is independent of anything else; this module never imports
     either symbol that does that work, and never calls `independent_confirmations`. A run
     from the same principal (or the same input-signature cluster) as an existing
     confirmation is recorded exactly like any other: the record is EVIDENCE, not a
     verdict, and refusing to record correlated evidence would hide it from the operator and
     from `workers.shadow_validator`'s own diagnostic count — both need to see every offered
     run, not only the ones that turned out to matter (PLAN.md §2 invariant 7's own test
     list: "Sybil test: two proposals / two same-principal traces do not exit quarantine" —
     that is a promotion-time refusal, not a recording-time one; the two same-principal
     traces are still ON THE ROW).

Two things this worker deliberately does NOT stamp, because the schema has nowhere to put
them and inventing a parameter for them would be a value nobody reads (D-122's alternative
(c), rejected there for the same reason): a per-append TIMESTAMP and a per-append
`epoch_id`. `shadow_confirm_runs` is a bare `uuid[]` — one element cannot carry a second
column — so "when was run X first recorded against memory Y, and under which judge pin"
has no answer in the shipped DDL. PLAN.md §5's "every Q update and shadow confirmation
records `epoch_id`" is satisfied one level up, at the TRANSITION this evidence eventually
justifies: `workers.shadow_validator.ShadowTransitionWrite.epoch_id`, which already carries
it and already explains why. That is why this worker takes no `Clock`: it has no
time-dependent behaviour and no timestamp to write, and a clock read whose value is passed
to a parameter no implementation can consume is exactly the kind of decorative wiring this
tree's audit was about. The gap is named in DECISIONS.md D-125 rather than papered over.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol, assert_never, runtime_checkable

from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import MAX_CONFIRMATIONS_CONSIDERED, Status
from tracebed.workers.shadow_validator import origin_runs

__all__ = [
    "AppendOutcome",
    "CorroborationBatchResult",
    "CorroborationCandidateSource",
    "CorroborationOutcome",
    "CorroborationRepoPort",
    "CorroborationWriter",
    "QuarantinedMemoryForCorroboration",
]


class AppendOutcome(Enum):
    """What a `CorroborationRepoPort.append_confirming_run` call actually did.

    Three values rather than a `bool`, because the three are NOT interchangeable and the
    statement that performs the append cannot avoid distinguishing them. A boolean
    "did I add it / was it already there" has no way to say "the row the append targeted no
    longer matched" — and that case is not hypothetical: the eligibility predicate is part
    of the same `WHERE` clause as the mutation (it has to be, or the append is not atomic),
    so a row archived by the quarantine-TTL sweep between this worker's select and its
    update produces exactly zero updated rows, identically to an already-present run. Folded
    into `False`, that reports a governance write as "recorded" when nothing was recorded and
    nothing ever will be — a plausible-looking success for a memory that has left quarantine.
    """

    APPENDED = "appended"
    """This call added `run_id` to `shadow_confirm_runs`."""
    ALREADY_PRESENT = "already_present"
    """The row is eligible and already carried `run_id`; nothing changed, and nothing needed
    to. Distinctness (PLAN.md §5: "distinct confirming run_ids") is preserved by the
    statement, not by a prior read."""
    ROW_NOT_ELIGIBLE = "row_not_eligible"
    """No row matched `(project_id, memory_id, status='quarantined')` — it left quarantine,
    was deleted, or never belonged to this project. NOT an error (a concurrent sweep is
    ordinary), but never "recorded" either."""


@dataclass(frozen=True, slots=True)
class QuarantinedMemoryForCorroboration:
    """The projection this worker needs to safely record a candidate confirmation.

    Deliberately narrower than `shadow_validator.QuarantinedMemoryRow`: this worker never
    reads `trust_tier`, `mem_type`, or `is_failure_lesson`, because it never judges
    promotion — only whether a run id is safe to record.

    `confirming_run_ids` is the store's current SNAPSHOT, read only for the
    `MAX_CONFIRMATIONS_CONSIDERED` growth guard and the "already recorded" fast path in
    `CorroborationWriter.record_one` — it is advisory, not authoritative: the repo call that
    actually mutates the row (`CorroborationRepoPort.append_confirming_run`) is the sole
    source of truth for whether a given run was already present, precisely because this
    snapshot can be stale under concurrent writers (see that method's docstring). A stale
    "already present" read is never wrong (the array is append-only — nothing ever removes
    a run id from it), which is what makes the fast path safe; a stale "not present" read is
    always re-checked by the repo call it leads to, which is what makes skipping that call
    unsafe and exactly why this worker never does.

    The one direction a stale snapshot IS dangerous is growth: a snapshot that under-reports
    the array's length under-reports how close the row is to `MAX_CONFIRMATIONS_CONSIDERED`.
    Inside one sweep that is this worker's own problem to solve and it does — `run_once`
    advances the snapshot as it writes, so the guard sees what the row now holds rather than
    what it held before the batch started.
    """

    id: MemoryId
    project_id: ProjectId
    status: Status
    provenance: Provenance
    confirming_run_ids: tuple[RunId, ...] = ()


@runtime_checkable
class CorroborationRepoPort(Protocol):
    def select_quarantined(
        self, project_id: ProjectId
    ) -> Sequence[QuarantinedMemoryForCorroboration]:
        """Indexed `(project_id, status='quarantined')` — the same cost discipline
        `ShadowValidatorRepoPort.select_quarantined` already established; never a trace
        scan."""
        ...

    def append_confirming_run(
        self, project_id: ProjectId, memory_id: MemoryId, run_id: RunId
    ) -> AppendOutcome:
        """Add `run_id` to `memory_item.shadow_confirm_runs` exactly once, atomically.

        CONCURRENCY CHOICE (an array append needs either a uniqueness guarantee in the
        statement or a dedup on read — this chunk picks the former, and this docstring is
        that choice recorded, per the task's own instruction to choose one and say which):
        uniqueness IN THE STATEMENT, not dedup-on-read.

        Dedup-on-read would mean: fetch the row, check `run_id not in shadow_confirm_runs`
        in Python, and if absent, issue an `UPDATE ... SET shadow_confirm_runs =
        array_append(...)`. Two workers racing that sequence for the SAME `(memory_id,
        run_id)` can both fetch before either commits, both see absence, and both append —
        an unlocked `SELECT` followed by an `UPDATE` holds nothing across the gap between
        them, so nothing stops the duplicate, and `shadow_confirm_runs` stops being the
        "distinct confirming run_ids" PLAN.md §5 says it is. `CorroborationWriter` never
        performs that sequence: it never re-derives "already present" from a row it read
        earlier as the basis for SKIPPING this call (see
        `QuarantinedMemoryForCorroboration`) — the only thing that may skip this call is an
        "already present" read, which is safe because the array is append-only and can never
        become stale in the direction that matters.

        A real implementation must therefore take the row's lock, and decide eligibility,
        membership and the mutation against THAT locked version, in one statement:

            WITH locked AS (
                SELECT id, status, shadow_confirm_runs
                  FROM memory_item
                 WHERE project_id = %(project_id)s AND id = %(memory_id)s
                   FOR NO KEY UPDATE
            ), updated AS (
                UPDATE memory_item m
                   SET shadow_confirm_runs = array_append(m.shadow_confirm_runs, %(run_id)s)
                  FROM locked l
                 WHERE m.project_id = %(project_id)s AND m.id = l.id
                   AND l.status = 'quarantined'
                   AND NOT (%(run_id)s = ANY(l.shadow_confirm_runs))
                RETURNING m.id
            )
            SELECT EXISTS (SELECT 1 FROM updated)             AS appended,
                   %(run_id)s = ANY(l.shadow_confirm_runs)    AS already_present,
                   l.status = 'quarantined'                   AS eligible
              FROM locked l

        Why this shape and not the shorter bare `UPDATE ... WHERE NOT (run_id = ANY(...))`:

        - `FOR NO KEY UPDATE` in `locked` is what makes the answer honest under a race. A
          racing writer for the same `run_id` blocks there; when it resumes, READ COMMITTED
          re-reads the latest committed row version, so `locked` already contains the other
          writer's append and both the `updated` guard and the reported `already_present`
          are computed against it. Relying instead on the bare `UPDATE`'s own EvalPlanQual
          re-check ties the correctness of this method to READ COMMITTED specifically —
          under REPEATABLE READ or SERIALIZABLE that same statement raises a serialization
          failure rather than quietly matching zero rows, so the caller would see an
          exception where this contract promises `ALREADY_PRESENT`. Taking the lock
          explicitly makes the three outcomes the same at every isolation level.
        - An empty result set (no `locked` row at all) is `ROW_NOT_ELIGIBLE`: the memory is
          gone or belongs to another project. `eligible = false` is the same answer for a
          row that left quarantine. Neither is distinguishable from `ALREADY_PRESENT` in a
          bare `UPDATE`'s row count, which is the whole reason `AppendOutcome` has three
          values.
        - No unique index or `ON CONFLICT` clause is needed or possible: the target is an
          array column, and the membership predicate evaluated against the locked row IS the
          uniqueness guarantee.

        The `project_id` predicate is present on both the lock and the update, and the
        implementing repo sets the RLS GUC for the transaction as every other statement in
        `stores/pg/` does — invariant 4 is not weakened by the row being reached twice.

        An implementation may additionally carry a provenance-derived predicate refusing a
        `run_id` that appears in the row's own `provenance` (the self-corroboration
        exclusion `record_one` applies below in Python, and `workers.shadow_validator`
        applies again, authoritatively, at judgment time). That would be a third,
        store-side copy of the same refusal; it is worth having because it holds for every
        writer rather than for this one, but it is not what makes invariant 7 true today and
        so is not specified here as SQL this chunk cannot execute.
        """
        ...


@runtime_checkable
class CorroborationCandidateSource(Protocol):
    def candidate_runs(
        self, project_id: ProjectId, row: QuarantinedMemoryForCorroboration
    ) -> Sequence[RunId]:
        """Every run_id currently OFFERED as a possible corroborating observation for this
        quarantined memory.

        Host/upstream-supplied — mirrors `workers.revalidation.RevalidationCheckPort`
        (deciding "what counts as re-verified" is not that worker's job either). Matching a
        run to a memory — exact `content_hash` recurrence from an independently distilled
        run, a webhook tying a later outcome back to a specific `memory_id`, an operator's
        manual flag — is a decision this module does not own or invent. A source that offers
        a run this worker cannot safely record (an origin run, an already-recorded run, one
        run past the cap, a row that has since left quarantine) is not an error on the
        source's part: `record_one` refuses it without raising and says why in
        `CorroborationOutcome.reason`, so an over-eager or stale source degrades to no-ops
        rather than to failures.

        Because this port is third-party code, `run_once` validates every row against the
        requested project BEFORE calling it — an implementation is never handed a row it
        would not have been allowed to see.
        """
        ...


@dataclass(frozen=True, slots=True)
class CorroborationOutcome:
    memory_id: MemoryId
    run_id: RunId
    recorded: bool
    """`True` iff `shadow_confirm_runs` demonstrably contains `run_id` now — because this
    call appended it, or because the store reported it already there. Never `True` on the
    strength of a snapshot alone when the store said otherwise: a row that left quarantine
    between the select and the append is `False` with a reason, not a silent success."""
    newly_added: bool
    """`True` only if THIS call is the one that appended `run_id`. `False` whenever
    `recorded` is `False`, and `False` for an idempotent repeat of an already-recorded run —
    `AppendOutcome.APPENDED` and nothing else."""
    reason: str
    """Empty iff `recorded`; otherwise why nothing was (or could be) written. Diagnostic
    only, exactly like `ShadowValidationOutcome.reason` — never parsed by a caller."""


@dataclass(frozen=True, slots=True)
class CorroborationBatchResult:
    rows_examined: int
    outcomes: tuple[CorroborationOutcome, ...]


class CorroborationWriter:
    def __init__(self, repo: CorroborationRepoPort) -> None:
        self._repo = repo

    def record_one(
        self,
        project_id: ProjectId,
        row: QuarantinedMemoryForCorroboration,
        run_id: RunId,
    ) -> CorroborationOutcome:
        """Attempt to record exactly one candidate confirming run against exactly one
        quarantined memory.

        Order of checks matters and is deliberate: project/status re-assertion first (the
        row must not even be looked at otherwise — see `_require_row`), then the
        self-corroboration exclusion UNCONDITIONALLY (an origin run is refused even if a
        buggy or malicious source also claims it is "already recorded" or would otherwise
        pass every later check — this is the one refusal invariant 7 can never let a stale
        snapshot or a confused source route around), then the cheap advisory fast paths, and
        only then the repo call that is the sole point of actual I/O.

        `row` is a projection the CALLER supplies, so its `provenance` is only as good as
        whoever read it. That is deliberate and sufficient: this refusal is the first of
        three, and the authoritative one is `workers.shadow_validator._resolve_confirmations`
        subtracting `origin_runs` from the row's own stored provenance at judgment time —
        so a fabricated or truncated provenance can at worst get a run id into the array,
        never past the guard.
        """
        _require_row(row, project_id)

        if run_id in origin_runs(row.provenance):
            return CorroborationOutcome(
                row.id,
                run_id,
                False,
                False,
                "run is one of this memory's own origin runs (provenance.trace_ids / the "
                "proposal run_id) -- a memory cannot corroborate itself (invariant 7)",
            )

        if run_id in row.confirming_run_ids:
            # Safe fast path, not an optimisation over correctness: shadow_confirm_runs is
            # append-only (nothing in this codebase removes a run id from it), so a snapshot
            # that already shows `run_id` present can never be wrong about that -- unlike
            # the absence case, which always falls through to the repo call below.
            return CorroborationOutcome(row.id, run_id, True, False, "")

        if len(row.confirming_run_ids) >= MAX_CONFIRMATIONS_CONSIDERED:
            # Defence in depth against unbounded growth from an attacker-influenced or
            # simply buggy candidate source, reusing (not inventing) the bound
            # `workers.independence.build_confirmations` already applies at judgment time --
            # a run turned away here changes storage only, never a promotion outcome: a row
            # already carrying MAX_CONFIRMATIONS_CONSIDERED entries has its judgment-time
            # confirmation count already capped at the same number regardless of what this
            # worker does next.
            return CorroborationOutcome(
                row.id,
                run_id,
                False,
                False,
                f"memory already has >= {MAX_CONFIRMATIONS_CONSIDERED} recorded confirmations "
                "(MAX_CONFIRMATIONS_CONSIDERED); refusing to grow shadow_confirm_runs further",
            )

        appended = self._repo.append_confirming_run(project_id, row.id, run_id)
        match appended:
            case AppendOutcome.APPENDED:
                return CorroborationOutcome(row.id, run_id, True, True, "")
            case AppendOutcome.ALREADY_PRESENT:
                return CorroborationOutcome(row.id, run_id, True, False, "")
            case AppendOutcome.ROW_NOT_ELIGIBLE:
                return CorroborationOutcome(
                    row.id,
                    run_id,
                    False,
                    False,
                    "no quarantined row matched at append time: the memory left quarantine, "
                    "was deleted, or is not in this project -- nothing was recorded",
                )
            case _ as unreachable:  # pragma: no cover - exhaustiveness is a mypy error
                assert_never(unreachable)

    def run_once(
        self, project_id: ProjectId, *, source: CorroborationCandidateSource
    ) -> CorroborationBatchResult:
        """Batch entry point: every currently-quarantined row, one indexed select, plus
        whatever `source` currently offers for each row.

        Every row is checked against `project_id` BEFORE `source` is consulted for any of
        them, and before a single append is issued. `source` is host-supplied code, so a
        select that over-returns would otherwise disclose another project's row (and its
        provenance) to a third party — and it would do so after this worker had already
        written to the rows preceding it in the batch. Validating the whole select first
        makes a broken store predicate a zero-write failure rather than a partial one.

        Within a row, the snapshot ADVANCES as runs are recorded. `record_one` is a pure
        function of the snapshot it is handed, so re-handing it the pre-batch snapshot for
        every offered run would make both of its snapshot-derived guards vacuous for the
        whole batch: the growth cap would compare a constant length against
        `MAX_CONFIRMATIONS_CONSIDERED` (a source offering ten thousand runs for a row with
        none would append all ten thousand — the cap only ever fires on the NEXT sweep), and
        the "already present" fast path would never fire, so the same run offered twice in
        one batch would cost two round trips. Both are properties of the COLUMN, which the
        batch is actively changing; carrying the change forward is what keeps them true.

        Wiring this into a live scheduler is outside this chunk's file list — the same M2
        worker-plane gap PLAN.md §11.1 already names for every other worker (`workers/
        runner.py` constructs `WorkerRunner(handlers={})`). This method exists so the batch
        behaviour itself is covered by a test that does not depend on that wiring, the same
        shape `workers.shadow_validator.run_once` and `workers.revalidation.run_once`
        already take.
        """
        rows = self._repo.select_quarantined(project_id)
        for row in rows:
            _require_row(row, project_id)

        outcomes: list[CorroborationOutcome] = []
        for row in rows:
            current = row
            for run_id in source.candidate_runs(project_id, row):
                outcome = self.record_one(project_id, current, run_id)
                outcomes.append(outcome)
                if outcome.recorded and run_id not in current.confirming_run_ids:
                    current = replace(
                        current, confirming_run_ids=(*current.confirming_run_ids, run_id)
                    )
        return CorroborationBatchResult(rows_examined=len(rows), outcomes=tuple(outcomes))


def _require_row(row: QuarantinedMemoryForCorroboration, project_id: ProjectId) -> None:
    """Re-assert both things a real `select_quarantined` promises, on every row, before
    acting on it — the same defensive re-assertion `workers.shadow_validator._require_row`
    and `workers.revalidation._require_row` already apply to their own selects' output, for
    the same reason: a select that over-returns is a control that has stopped holding, not
    one bad row, and this worker's write (an array append) is silent enough that a wrong-
    project or wrong-status append would not surface any other way.
    """
    if row.project_id != project_id:
        raise TracebedError(
            f"memory {row.id} belongs to project {row.project_id}, not {project_id}; "
            f"select_quarantined returned a row outside the requested project (invariant 4)"
        )
    if row.status is not Status.QUARANTINED:
        raise TracebedError(
            f"memory {row.id} is {row.status.value!r}, not 'quarantined'; corroboration "
            f"must not record a confirming run against a memory that has already left "
            f"quarantine (quarantined rows only)"
        )
