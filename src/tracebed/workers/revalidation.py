"""Usage-triggered revalidation at `lifecycle.revalidation_age_days` (R) — PLAN.md §7 Phase 2.

Two checks share one state-machine vocabulary (`stale -> validated`: re-verification pass;
`stale -> retired`: second strike):

  - `check_validated`: a `validated` memory that has gone `R` days without being retrieved
    (or, if never retrieved, `R` days since it was created) is due for re-verification. A
    failing re-verification is STRIKE ONE: `validated -> stale`, `strike_count` set to 1 —
    the same convention `workers.invalidator` uses for every other route into `stale`, which
    is what makes `stale -> retired`'s guard (`strike_count >= 2`) reachable by exactly one
    more failure and never by a row that started at zero.
  - `check_stale`: `stale` memories are excluded from
    `state_machine.RETRIEVABLE_STATUSES`, so nothing can ever trigger their re-check by
    usage — this half is necessarily periodic/batch-driven (`run_once` below), not
    usage-triggered. A passing re-verification recovers the memory (`stale -> validated`,
    `strike_count` reset to 0); a second failure retires it (`stale -> retired`).

"Two strikes, not one — a single transient verification failure retiring a good memory is
how a fleet loses its accumulated knowledge to a flaky upstream" (task description).

`RevalidationCheckPort` is host-supplied: what "re-verify this memory" means is itself an
LLM-free operational check (re-run a Tier A parser, re-read an environment fact, ...) this
chunk does not own or invent — it is a pure `LifecycleMemoryRow -> bool` decision handed to
this worker by whoever wires it to a real check.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.workers.invalidator import (
    LifecycleMemoryRow,
    LifecycleTransitionWrite,
    MemoryLifecycleRepoPort,
)

__all__ = [
    "RevalidationBatchResult",
    "RevalidationCheckPort",
    "RevalidationOutcome",
    "RevalidationWorker",
    "is_due_for_revalidation",
]


@runtime_checkable
class RevalidationCheckPort(Protocol):
    def reverify(self, row: LifecycleMemoryRow) -> bool:
        """True = the memory still checks out; False = the check failed (a strike)."""
        ...


def is_due_for_revalidation(row: LifecycleMemoryRow, *, r_days: int, now: datetime) -> bool:
    """Pure boundary test: exactly R days and not before.

    A `validated` row is due once its idle reference (`last_retrieved_at`, or `created_at` if
    never retrieved) is at least `r_days` old.

    A `stale` row is due on any LATER instant than the one it entered `stale` on. It cannot
    be retrieved (excluded from `state_machine.RETRIEVABLE_STATUSES`), so nothing else will
    ever ask about it again and no R-day idle window applies — but "second strike" names a
    second OCCASION, and `now == status_changed_at` is the first one being read twice.
    Without this, running the batch twice against one frozen instant (a retry, a duplicated
    scheduler tick, a soak replaying a simulated day) took a memory from `validated` to
    `retired` with a single verifier verdict standing in for both strikes. A row whose
    `status_changed_at` is NULL (the column is nullable — migrations/0002) is due, because
    there is then no first occasion to be distinct from.

    Every other status is never due.
    """
    if row.status is Status.STALE:
        return row.status_changed_at is None or now > row.status_changed_at
    if row.status is not Status.VALIDATED:
        return False
    reference = row.last_retrieved_at if row.last_retrieved_at is not None else row.created_at
    return now - reference >= timedelta(days=r_days)


@dataclass(frozen=True, slots=True)
class RevalidationOutcome:
    memory_id: MemoryId
    verified: bool
    from_status: Status
    to_status: Status | None
    """`None` means "checked, verified, nothing transitioned" (the `validated`, passing
    case) — every other outcome carries the status `state_machine.apply()` returned."""


@dataclass(frozen=True, slots=True)
class RevalidationBatchResult:
    rows_examined: int
    outcomes: tuple[RevalidationOutcome, ...]


class RevalidationWorker:
    def __init__(self, repo: MemoryLifecycleRepoPort, clock: Clock) -> None:
        self._repo = repo
        self._clock = clock

    def check_validated(
        self,
        project_id: ProjectId,
        row: LifecycleMemoryRow,
        *,
        verifier: RevalidationCheckPort,
        cfg: EffectiveConfig,
    ) -> RevalidationOutcome:
        """Only for `row.status is Status.VALIDATED`; callers (`run_once` below, or a host
        pipeline) decide a row is due via `is_due_for_revalidation` first.

        A row on any other status is refused rather than processed. Handing this method a
        `quarantined` row previously wrote `from_status=validated, to_status=stale` for it —
        `apply()` was called, but with a fabricated `current`, so the machine authorised an
        edge (`quarantined -> stale`) that PLAN.md §5's table does not contain and never
        saw the row's real status.
        """
        _require_row(row, project_id, Status.VALIDATED)
        now = self._clock.now()
        verified = verifier.reverify(row)

        if verified:
            # Nothing about the row's STATUS changed, so there is nothing for apply() to
            # authorise — this is a plain field touch (see MemoryLifecycleRepoPort.persist).
            self._repo.persist(
                project_id,
                LifecycleTransitionWrite(
                    memory_id=row.id,
                    from_status=Status.VALIDATED,
                    to_status=Status.VALIDATED,
                    now=now,
                    last_revalidated_at=now,
                ),
            )
            return RevalidationOutcome(row.id, True, Status.VALIDATED, None)

        limits = TransitionLimits.from_config(cfg)
        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
            revalidation_failed=True,
        )
        new_status = apply(row.status, Status.STALE, evidence, limits)
        self._repo.persist(
            project_id,
            LifecycleTransitionWrite(
                memory_id=row.id,
                from_status=row.status,
                to_status=new_status,
                now=now,
                strike_count=1,  # first route into `stale` — see workers.invalidator's note
                last_revalidated_at=now,
            ),
        )
        return RevalidationOutcome(row.id, False, row.status, new_status)

    def check_stale(
        self,
        project_id: ProjectId,
        row: LifecycleMemoryRow,
        *,
        verifier: RevalidationCheckPort,
        cfg: EffectiveConfig,
    ) -> RevalidationOutcome:
        """Only for `row.status is Status.STALE` — any other status is refused, for the same
        reason `check_validated` refuses one (a fabricated `current` makes `apply()` judge an
        edge the row is not on)."""
        _require_row(row, project_id, Status.STALE)
        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)
        verified = verifier.reverify(row)

        if verified:
            evidence = TransitionEvidence(
                now=now,
                provenance_class=row.provenance.cls,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                status_changed_at=row.status_changed_at,
                reverified=True,
            )
            new_status = apply(row.status, Status.VALIDATED, evidence, limits)
            self._repo.persist(
                project_id,
                LifecycleTransitionWrite(
                    memory_id=row.id,
                    from_status=row.status,
                    to_status=new_status,
                    now=now,
                    strike_count=0,  # recovered — the two-strike counter starts over
                    last_revalidated_at=now,
                ),
            )
            return RevalidationOutcome(row.id, True, row.status, new_status)

        # Every route into `stale` (workers.invalidator, and check_validated above) writes
        # strike_count=1, so a second failure while stale is provably >= the guard's
        # threshold of 2 — but the guard is invoked for real, not assumed: a row that
        # somehow entered `stale` with strike_count=0 surfaces as GuardNotSatisfied instead
        # of silently retiring on its first failure ("one strike does not retire").
        next_strike = row.strike_count + 1
        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
            strike_count=next_strike,
        )
        new_status = apply(row.status, Status.RETIRED, evidence, limits)
        self._repo.persist(
            project_id,
            LifecycleTransitionWrite(
                memory_id=row.id,
                from_status=row.status,
                to_status=new_status,
                now=now,
                strike_count=next_strike,
                last_revalidated_at=now,
            ),
        )
        return RevalidationOutcome(row.id, False, row.status, new_status)

    def run_once(
        self, project_id: ProjectId, *, verifier: RevalidationCheckPort, cfg: EffectiveConfig
    ) -> RevalidationBatchResult:
        """Batch entry point: every due `validated` row plus every due `stale` row (`stale`
        is never usage-triggered — see module docstring). Two indexed selects only
        (`select_due_for_revalidation`, `select_by_status`) — never a trace scan.

        ONE PASS DELIVERS AT MOST ONE STRIKE. Two mechanisms, because either alone is a way
        for one verifier verdict to carry a memory from `validated` all the way to `retired`:

        * `struck_this_pass` excludes rows this call just moved into `stale` from the stale
          loop. Previously that only held because `select_by_status` happened to be called
          before the validated loop ran — reordering two statements, or a store whose select
          is lazy rather than materialised, silently turned two strikes into one.
        * `is_due_for_revalidation` refuses a `stale` row whose `status_changed_at` is this
          same instant, which covers the second call rather than the second loop: a retry or
          a duplicated tick against a frozen clock.
        """
        now = self._clock.now()
        r_days = cfg.lifecycle.revalidation_age_days
        due_validated = self._repo.select_due_for_revalidation(
            project_id, older_than=now - timedelta(days=r_days)
        )
        stale_rows = [
            row
            for row in self._repo.select_by_status(project_id, [Status.STALE])
            if is_due_for_revalidation(row, r_days=r_days, now=now)
        ]

        outcomes: list[RevalidationOutcome] = []
        struck_this_pass: set[MemoryId] = set()
        for row in due_validated:
            outcome = self.check_validated(project_id, row, verifier=verifier, cfg=cfg)
            outcomes.append(outcome)
            if outcome.to_status is Status.STALE:
                struck_this_pass.add(row.id)
        for row in stale_rows:
            if row.id in struck_this_pass:
                continue
            outcomes.append(self.check_stale(project_id, row, verifier=verifier, cfg=cfg))

        return RevalidationBatchResult(
            rows_examined=len(due_validated) + len(stale_rows), outcomes=tuple(outcomes)
        )


def _require_row(row: LifecycleMemoryRow, project_id: ProjectId, expected: Status) -> None:
    """Re-assert BOTH things `select_due_for_revalidation` / `select_by_status` promised,
    on every row, before acting on it.

    Project scope first (invariant 4). This is the same post-condition `sweeps
    ._require_returned_row` and `invalidator.process_event` already re-assert against the
    same `MemoryLifecycleRepoPort`, and it was the one lifecycle worker of the three that
    did not — an inconsistency no per-chunk audit could see, because each chunk read only
    its own module. It matters more here than anywhere: `check_stale` RETIRES on the second
    strike, so a foreign-project row reaching this worker is a foreign project's memory
    retired by this project's verifier, with the write then routed to `persist(project_id,
    ...)` — the wrong project's partition — so the row an operator went looking for would
    not be the row that changed. The predicate lives in a store implementation that does
    not exist yet (contract gap, `workers.invalidator`'s module docstring), so nothing but
    this check stands between an over-broad selector and that outcome.

    Raising rather than skipping, for the reason the sibling workers give: a select that
    returned another project's row is a control that has stopped holding, not one bad row.
    """
    if row.project_id != project_id:
        raise TracebedError(
            f"memory {row.id} belongs to project {row.project_id}, not {project_id}; "
            f"the revalidation select returned a row outside the requested project"
        )
    _require_status(row, expected)


def _require_status(row: LifecycleMemoryRow, expected: Status) -> None:
    """Refuse a row that is not on the status this check is written for.

    A `TracebedError` rather than an `IllegalTransition`, because no specific illegal edge
    has been named yet — the defect is upstream of choosing one, and `IllegalTransition`
    would have to invent a `(current, target)` pair that is sometimes perfectly legal
    (`stale` handed to `check_validated` would report `validated -> stale`, a real edge).
    """
    if row.status is not expected:
        raise TracebedError(
            f"memory {row.id} is {row.status.value!r}, not {expected.value!r}; this "
            f"revalidation check would otherwise ask the state machine to judge an edge "
            f"the row is not on"
        )
