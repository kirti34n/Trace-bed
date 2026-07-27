"""Preferences / persona pinning -- the explicit operator edit flow for the ONE ungoverned
status (PLAN.md §5 SM-01 / D-014; PLAN.md §7 Phase 4: "preferences/persona pinning (`pinned`
status, explicit edit flow)").

`pinned` is THE explicit ungoverned status, and it is for preferences ONLY. Everything else
in this module exists to keep that true at the one place a bypass would matter:

1. PINNING A NON-PREFERENCE IS REFUSED TWICE, INDEPENDENTLY, BEFORE ANY I/O.
   `state_machine._guard_none_to_pinned` refuses any `mem_type` other than
   `MemType.PREFERENCE` for the `None -> pinned` edge, and `pin()` below refuses it FIRST --
   before the scan suite runs and before a `TransitionEvidence` is even built -- naming the
   actual reason: pinning a lesson or a semantic fact would create an IMMORTAL ungoverned
   memory. Concretely, pinned is the one status every lifecycle worker's own selection query
   silently omits -- `workers.sweeps.quarantine_ttl_sweep` / `candidate_ttl_sweep` /
   `decay_sweep` and `workers.promotion.PromotionWorker.run_retirement_once` all read an
   INDEXED `memory_item` population scoped to one specific *governed* status (`quarantined`,
   `candidate`, `validated`) and never to `pinned` -- so a pinned row that should not exist
   skips decay, skips both TTL sweeps, and skips retirement forever, with nothing in this
   codebase ever re-examining it.

   The second refusal is only real because the caller's `mem_type` is what travels into
   `_pinning_evidence` (and into the `ScanContext` and the `NewMemoryItem`). Hard-coding
   `MemType.PREFERENCE` at those three sites -- which is what this module did until the
   Phase 4 audit -- makes `_guard_none_to_pinned`'s `mem_type` check tautological: the
   boundary refusal becomes the ONLY control, and deleting it would not raise, it would
   silently relabel a lesson as a preference and pin it. `_pinning_evidence` is a separate
   module-level function precisely so `tests/phase4/test_preferences.py` can put the exact
   evidence `pin()` submits through `apply()` on its own and watch the machine refuse it.

2. UNPINNING IS THE MACHINE'S OWN ONE LEGAL EXIT, NOT SOMETHING THIS MODULE INVENTS.
   PHASE0-CONTRACT.md §3.9 pins `pinned`'s participation exhaustively: "`pinned` participates
   in exactly: `None→pinned`, `pinned→tombstoned`." There is no `pinned -> quarantined` /
   `-> candidate` / `-> validated` edge anywhere in `domain.state_machine.TRANSITIONS`, and
   adding one would mean writing to `domain/state_machine.py`, which is outside this chunk's
   file list (hard rule 7) and owned, frozen, by chunk `domain-state-machine`. "Unpinning
   returns [a preference] to governance" is therefore implemented as exactly what the one
   legal edge means: the row stops being permanently exempt from the state machine's own
   handling the instant `apply()` is asked to judge its fate again, via
   `pinned -> tombstoned` with `erasure_or_approved_delete=True` -- the SAME governed
   transition every other terminal exit in this codebase uses (`workers.edit_ops
   .EditOps.delete_by_subject`, `workers.invalidator`'s stale->retired path, and so on).
   `unpin()` calls `apply()` for that edge and persists exactly what it returns, like every
   other write in this module: it never computes a status of its own. Content is preserved on
   the tombstoned row; crypto-shredding a subject's KEK is a SEPARATE, unrelated act
   (`workers.edit_ops.EditOps.delete_by_subject`) that this module does not perform, and
   re-admitting the same content under governed provenance (e.g. a fresh `propose_memory`
   submission, or distiller output) is a distinct, later operation, not something `unpin`
   does on the caller's behalf.

Repository shape: `MemoryEditRepoPort` / `EditableMemory` / `MemoryStatusWrite` are imported
from `workers.edit_ops` rather than redefined here -- the same "one shared shape read by
several sibling workers" pattern `workers.sweeps` already uses for
`workers.invalidator.MemoryLifecycleRepoPort` (a real `Repo` needs exactly one adapter to
satisfy every worker that reads/writes a `memory_item` row this way, not one per worker).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from tracebed.core.scans import ScanContext, scan
from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId
from tracebed.domain.memory import NewMemoryItem, Provenance, validate_provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.workers.edit_ops import EditableMemory, MemoryEditRepoPort, MemoryStatusWrite

__all__ = [
    "NotAPreference",
    "PinResult",
    "PreferenceManager",
    "UnpinResult",
]


def _pinning_evidence(*, now: datetime, mem_type: MemType, scan_passed: bool) -> TransitionEvidence:
    """THE evidence `pin()` submits for `None -> pinned`, built here rather than inline.

    Point 1 of the module docstring: the whole value of `_guard_none_to_pinned` re-asserting
    "preferences only" is that `mem_type` arrives from the caller and is never replaced with
    a constant on the way. Isolating that construction is what lets a test drive
    `apply(None, PINNED, _pinning_evidence(mem_type=LESSON, ...), limits)` and observe the
    machine's own refusal, instead of asserting the second line of defense exists in prose.
    """
    return TransitionEvidence(
        now=now,
        provenance_class=ProvenanceClass.OPERATOR,
        trust_tier=TrustTier.A,
        mem_type=mem_type,
        scan_passed=scan_passed,
        provenance_complete=True,  # validate_provenance() ran at the call site
        operator_created=True,
    )


class NotAPreference(ValueError):
    """Raised at the pin boundary for any `mem_type` other than `PREFERENCE` -- see point 1
    of the module docstring. A `ValueError` subclass (not a bare `ValueError`) so a caller
    that wants to distinguish "you asked me to pin the wrong kind of memory" from every other
    `pin()` misuse (a naive timestamp, a malformed scope) can catch it by name."""


def _estimate_token_count(content: str) -> int:
    """Mirrors `workers.edit_ops._estimate_token_count` / `workers.distiller._estimate_tokens`
    exactly, for the identical reason: no canonical tokenizer exists anywhere in this codebase
    for `memory_item.token_count` (shared CONTRACT GAP), and `pinned` rows are the one memory
    class placed in EVERY run's static prefix (`workers.prefix_builder`), so the count must be
    derived from the bytes actually stored, never accepted from a caller. Reimplemented here,
    not imported, because the source is a private, underscore-prefixed helper on a sibling
    module this chunk does not own."""
    return max(1, len(content) // 4)


def _require_project(row: EditableMemory, project_id: ProjectId, *, source: str) -> None:
    """Re-assert project scope on every row before acting on it -- the same defensive
    re-check `workers.edit_ops`/`workers.invalidator`/`workers.sweeps`/`workers.promotion` all
    perform on their own store reads (invariant 4): a select that returns a foreign-project
    row is an isolation failure, not a row to silently act on."""
    if row.project_id != project_id:
        raise TracebedError(
            f"{source} returned memory {row.id} scoped to project {row.project_id}, not "
            f"the requested {project_id} (invariant 4)"
        )


@dataclass(frozen=True, slots=True)
class PinResult:
    memory_id: MemoryId
    status: Status


@dataclass(frozen=True, slots=True)
class UnpinResult:
    memory_id: MemoryId
    from_status: Status
    to_status: Status
    """Always `Status.TOMBSTONED` -- the one legal edge out of `pinned` (see point 2 of the
    module docstring). Carried as a field, rather than hard-coded at the call site, so a
    caller reads it the same way every other transition-result dataclass in this codebase
    reports what `apply()` actually returned."""


class PreferenceManager:
    """Pin and unpin preferences. `repo` is this module's own `MemoryEditRepoPort` (imported
    from `workers.edit_ops`, not redefined); `clock` is the one injected time source every
    transition's `now` and the scan suite's `issued_at_ms` are read from (hard rule 3)."""

    def __init__(self, repo: MemoryEditRepoPort, clock: Clock) -> None:
        self._repo = repo
        self._clock = clock

    # -- pin ------------------------------------------------------------------------

    def pin(
        self,
        project_id: ProjectId,
        *,
        mem_type: MemType,
        content: str,
        principal_id: PrincipalId,
        scope_type: ScopeType,
        scope_id: UUID | None,
        cfg: EffectiveConfig,
        kind: str = "preference",
        subject_tag: str | None = None,
    ) -> PinResult:
        """PLAN.md §5 row 3: `None -> pinned`. Refuses anything but
        `mem_type=MemType.PREFERENCE` before any I/O runs (point 1 of the module docstring);
        `_guard_none_to_pinned` re-asserts the identical rule inside `apply()` below on the
        caller's OWN `mem_type`, so neither control stands alone.

        `token_count` is DERIVED from `content`, never accepted -- see
        `_estimate_token_count` for why a caller-supplied count on this exact memory class
        is a static-prefix budget bypass, not a convenience.
        """
        if mem_type is not MemType.PREFERENCE:
            raise NotAPreference(
                f"pin() refuses mem_type={mem_type.value!r}: `pinned` is the explicit "
                "ungoverned status for preferences ONLY (PHASE0-CONTRACT.md §3.9 -- "
                "'None→pinned' requires mem_type PREFERENCE); pinning a lesson or a "
                "semantic fact would create an immortal ungoverned memory that no decay "
                "sweep, TTL sweep, or retirement pass in this codebase ever selects"
            )

        ctx = ScanContext(
            project_id=project_id,
            mem_type=mem_type,
            trust_tier=TrustTier.A,
            provenance_class=ProvenanceClass.OPERATOR,
            lane=Lane.OPERATIONAL,
        )
        result = scan(content, context=ctx)
        verdict = result.verdict(clock=self._clock)  # raises ScanRejected if not passed

        provenance = Provenance(cls=ProvenanceClass.OPERATOR, principal=principal_id)
        validate_provenance(provenance)  # invariant 6, earned here rather than asserted below

        limits = TransitionLimits.from_config(cfg)
        new_status = apply(
            None,
            Status.PINNED,
            _pinning_evidence(
                now=self._clock.now(), mem_type=mem_type, scan_passed=result.passed
            ),
            limits,
        )

        item = NewMemoryItem(
            scope_type=scope_type,
            scope_id=scope_id,
            mem_type=mem_type,
            kind=kind,
            lane=Lane.OPERATIONAL,
            trust_tier=TrustTier.A,
            status=new_status,
            content=content,
            token_count=_estimate_token_count(content),
            provenance=provenance,
            subject_tag=subject_tag,
        )
        memory_id = self._repo.insert_memory_item(project_id, item, verdict)
        return PinResult(memory_id=memory_id, status=new_status)

    # -- unpin ----------------------------------------------------------------------

    def unpin(self, project_id: ProjectId, memory_id: MemoryId, *, cfg: EffectiveConfig) -> UnpinResult:
        """The one legal exit from `pinned` (point 2 of the module docstring):
        `pinned -> tombstoned`, `erasure_or_approved_delete=True`. Refuses (with a plain
        `ValueError`, before touching `apply()`) any row whose live status is not
        `Status.PINNED` -- there is no other edge this method is for, and asking `apply()`
        to judge `(some_other_status, TOMBSTONED)` here would still be a legal transition
        for a different reason (the wildcard `*->tombstoned` row), silently doing something
        this method never claims to do.
        """
        row = self._repo.get_memory_by_id(project_id, memory_id)
        _require_project(row, project_id, source="get_memory_by_id")
        if row.status is not Status.PINNED:
            raise ValueError(
                f"unpin() refuses memory {memory_id}: status is {row.status.value!r}, not "
                "'pinned' -- only a currently-pinned row can be unpinned"
            )

        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)
        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
            erasure_or_approved_delete=True,
        )
        # `row.status`, not the literal `Status.PINNED`: the machine must judge the edge the
        # row is actually on (tests/phase2/test_write_path_seams.py's seam guard) -- the
        # `row.status is not Status.PINNED` refusal just above is what makes this the same
        # edge either way, but the call site must read the row, never assume it.
        new_status = apply(row.status, Status.TOMBSTONED, evidence, limits)
        self._repo.persist_status(
            project_id,
            MemoryStatusWrite(
                memory_id=memory_id, from_status=Status.PINNED, to_status=new_status, now=now
            ),
        )
        return UnpinResult(memory_id=memory_id, from_status=Status.PINNED, to_status=new_status)
