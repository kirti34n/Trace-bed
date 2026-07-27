"""Operator edit operations: pin, delete-by-subject, merge, operator_edit (PLAN.md §7
Phase 3; PLAN.md §10 "no admin bypass exists in code").

These four operations LOOK administrative -- a dashboard button that deletes, merges, or
overwrites a memory -- and that is exactly why hard rule 5 singles them out: "there is no
admin bypass exists in code and you must not add one -- operator actions and erasure are
themselves transitions." Every status this module writes is whatever
`domain.state_machine.apply()` returned for that exact call; nothing here computes or
guesses a `Status` any other way, and an illegal edge (attempting to merge a
non-`validated` source, or editing an already-`tombstoned` memory) is refused by
`apply()` raising `IllegalTransition`/`GuardNotSatisfied` -- there is no pre-check in this
module that duplicates the machine's own refusal.

  * `pin` -- PLAN.md §5 row 3 (`None -> pinned`): the ONE creation edge OPERATOR
    provenance actually has. Preferences only (`_guard_none_to_pinned` requires
    `mem_type == PREFERENCE`); goes through `core.scans` like every other insert
    (invariant 6: no write path skips the scan suite, preferences included).
  * `delete_by_subject` -- crypto-shredding (`crypto.shred.SubjectKeyManager.destroy_subject`)
    destroys the subject's KEK, and every `memory_item` tagged with that subject is
    additionally tombstoned through `apply()` (`erasure_or_approved_delete=True`,
    PLAN.md §5's wildcard `*->tombstoned` row). Two independent effects, both erasure:
    the trace payload's subject sections become cryptographically unreadable (§6,
    `crypto/shred.py` -- already tested there), and any GOVERNED memory carrying that
    subject_tag is tombstoned (this module's job).
  * `merge` -- combines >= 2 `validated` sources by superseding each of them
    (`validated -> superseded`, `contradiction_equal_or_stronger=True` -- an operator
    merge decision is definitionally an equal-or-stronger authority over the sources it
    merges). A non-`validated` source is refused by `apply()` itself
    (`IllegalTransition`), not by a pre-check here.
  * `operator_edit` -- D-032: "a human editing a memory on the dashboard; not an
    adapter, bypasses the scorer, supersedes directly (a state-machine transition)."
    Implemented as exactly that one transition (`validated -> superseded`,
    `contradiction_equal_or_stronger=True`) on the OLD row.

    CONTRACT GAP (reported, not deviated from): `domain.state_machine.TRANSITIONS`
    (frozen; owned by chunk `domain-state-machine`, outside this chunk's file list) has
    no creation edge into any RETRIEVABLE status for `ProvenanceClass.OPERATOR` content
    outside `mem_type == PREFERENCE` -- `None -> candidate` requires PARSER provenance,
    `None -> quarantined` requires DISTILLER/PROPOSAL, and `None -> pinned` requires
    `mem_type == PREFERENCE`. D-032 describes ONLY the supersede transition for
    `operator_edit` ("supersedes directly (a state-machine transition)"), and that half
    is implemented here in full, tested, and refuses illegal edges through `apply()`
    exactly like the other three ops. Inserting the operator's REPLACEMENT content as an
    immediately-retrievable row has no legal edge to call `apply()` with today; doing so
    anyway would mean either misrepresenting the new row's `provenance.cls` (claiming
    PARSER/DISTILLER for human-authored content -- a provenance lie invariant 6 exists to
    prevent) or adding a new `TRANSITIONS` entry (a file outside this chunk's ownership,
    and precisely the kind of change PLAN.md §10 says must never be a quiet workaround).
    `OperatorEditResult` reports the superseded old row; wiring the replacement insert is
    left to whoever next owns `domain/state_machine.py`.

Every method below re-fetches nothing it did not just receive: `MemoryEditRepoPort` is
this chunk's own Protocol (`Repo` has no `select_by_subject_tag`/`persist_status` at all
-- a real contract gap, distinct from the state-machine one above -- and returns
`stores.pg.rows.MemoryItemRow` from `get_memory_by_id`, not this module's smaller
`EditableMemory` projection; a thin adapter is the natural next step for whoever wires
this to the real `Repo`). `insert_memory_item`'s signature IS the real `Repo` method's
signature verbatim, so that one piece needs no adapter at all.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from tracebed.core.scans import ScanContext, scan
from tracebed.crypto.shred import SubjectKeyManager
from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.scan import ScanVerdict
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply

__all__ = [
    "DeleteBySubjectResult",
    "EditOps",
    "EditableMemory",
    "MemoryEditRepoPort",
    "MemoryStatusWrite",
    "MergeResult",
    "OperatorEditResult",
    "PinResult",
]


def _estimate_token_count(content: str) -> int:
    """Mirrors `workers.extractors.base._estimate_token_count` exactly, and
    `workers.distiller._estimate_tokens` with it -- the same CONTRACT GAP applies (no
    canonical tokenizer exists anywhere in this codebase for `memory_item.token_count`).

    `pin` derives this rather than accepting it, which is what the other two write paths
    already do. A caller-supplied count is not merely inconsistent: `pinned` rows are the
    ONE memory class placed in the static prefix of every single run of an agent type, and
    `workers.prefix_builder` fills that prefix by summing `row.token_count` against
    `budget.static_prefix`. A count that disagrees with the content -- an operator UI that
    estimates with a different tokenizer, or simply passes 1 -- silently overruns a budget
    PLAN.md §6 states as a hard cap, on the memory class with the widest blast radius.
    Deriving it means the number and the bytes cannot disagree.
    """
    return max(1, len(content) // 4)


def _require_aware(name: str, value: datetime | None) -> datetime | None:
    """Mirrors `TransitionEvidence.__post_init__`'s own refusal (state_machine.py):
    a naive `status_changed_at` either crashes `apply()`'s TTL subtraction with a bare
    `TypeError` or, worse, silently compares against the wrong instant."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{name} must be timezone-aware; got a naive datetime")
    return value


@dataclass(frozen=True, slots=True)
class EditableMemory:
    """The projection of a `memory_item` row every op in this module needs: enough to
    build a `TransitionEvidence` and to re-assert project scope, plus `subject_tag`
    (needed by `delete_by_subject`, and absent from `workers.invalidator.LifecycleMemoryRow`
    -- that dataclass is the closest existing sibling shape but does not carry it, so a
    separate projection lives here rather than forcing an unrelated chunk's row type to
    grow a field this chunk needs)."""

    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    provenance: Provenance
    status_changed_at: datetime | None
    subject_tag: str | None

    def __post_init__(self) -> None:
        _require_aware("EditableMemory.status_changed_at", self.status_changed_at)


@dataclass(frozen=True, slots=True)
class MemoryStatusWrite:
    """One committed status write. `to_status` is always whatever `state_machine.apply()`
    just returned for this exact call -- never a literal this module invents."""

    memory_id: MemoryId
    from_status: Status
    to_status: Status
    now: datetime
    actor_principal: PrincipalId | None = None
    """The authenticated human who caused this transition, when one did. PLAN.md §10:
    "operator actions and erasure are themselves transitions" -- a transition whose actor
    is dropped at the write seam is a governed status change with no audit trail, and
    `operator_edit` accepted a `principal_id` it recorded only in its own return value.
    `None` for machine-driven transitions (nothing here fabricates an actor)."""

    def __post_init__(self) -> None:
        """Two refusals at the write seam, because this dataclass is exported and a
        `persist_status(project_id, MemoryStatusWrite(...))` built by hand is the exact
        shape an admin bypass would take (PLAN.md §10). Neither check can prove `apply()`
        authorised the pair -- only `apply()` can -- but both reject shapes `apply()`
        provably never produces.

        (a) `now` becomes the row's next `status_changed_at`, which is precisely the value
        every TTL guard in `state_machine` subtracts from `evidence.now`. A naive value
        there reintroduces the exact skew `TransitionEvidence.__post_init__` and this
        module's own `_require_aware` (applied to the READ side, `EditableMemory
        .status_changed_at`) exist to stop -- checking one half of the round trip and not
        the other leaves the hole open in the direction that writes.

        (b) `from_status == to_status` is not a transition. `TRANSITIONS` contains no
        self-edge (`TOMBSTONED` is terminal, so even the wildcard `*->tombstoned` expansion
        excludes `(TOMBSTONED, TOMBSTONED)`), so `apply()` cannot return a status equal to
        its `current`; a write claiming one did not come from the machine.
        """
        _require_aware("MemoryStatusWrite.now", self.now)
        if self.from_status is self.to_status:
            raise ValueError(
                f"MemoryStatusWrite is not a transition: from_status == to_status == "
                f"{self.from_status.value!r}; state_machine.apply() never returns its own "
                f"`current` (there is no self-edge in TRANSITIONS)"
            )


@runtime_checkable
class MemoryEditRepoPort(Protocol):
    """What `EditOps` needs from a memory store, beyond what the real `Repo` already
    implements (see the module docstring's contract-gap note)."""

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> EditableMemory:
        """Same name as `stores.pg.repo.Repo.get_memory_by_id` -- a real `Repo` needs only
        a projection adapter (`MemoryItemRow -> EditableMemory`) to satisfy this, not a
        new query."""
        ...

    def select_by_subject_tag(
        self, project_id: ProjectId, subject_tag: str
    ) -> Sequence[EditableMemory]:
        """CONTRACT GAP: `Repo` has no query indexed on `memory_item.subject_tag` today."""
        ...

    def persist_status(self, project_id: ProjectId, write: MemoryStatusWrite) -> None:
        """CONTRACT GAP: `Repo` has no `UPDATE memory_item SET status = ...` path at all
        -- only `insert_memory_item` (a fresh row) exists today."""
        ...

    def insert_memory_item(
        self, project_id: ProjectId, item: NewMemoryItem, scan_verdict: ScanVerdict
    ) -> MemoryId:
        """Exactly `Repo.insert_memory_item`'s real signature -- the real `Repo` satisfies
        this piece with zero adapter code."""
        ...


@dataclass(frozen=True, slots=True)
class PinResult:
    memory_id: MemoryId
    status: Status


@dataclass(frozen=True, slots=True)
class DeleteBySubjectResult:
    subject_tag: str
    key_destroyed: bool
    """`SubjectKeyManager.destroy_subject`'s own return: `False` iff the subject never had
    a KEK row at all (idempotent -- re-destroying an already-destroyed key is `True`)."""
    tombstoned_memory_ids: tuple[MemoryId, ...]
    already_tombstoned_memory_ids: tuple[MemoryId, ...]
    """Rows `select_by_subject_tag` returned that were already `tombstoned` -- skipped
    without calling `apply()`, because `(TOMBSTONED, TOMBSTONED)` is not in `TRANSITIONS`
    at all (tombstoned is the machine's one terminal status) and re-tombstoning an
    already-erased row is not a status change, it is a no-op that must not raise."""


@dataclass(frozen=True, slots=True)
class MergeResult:
    superseded_memory_ids: tuple[MemoryId, ...]


@dataclass(frozen=True, slots=True)
class OperatorEditResult:
    memory_id: MemoryId
    from_status: Status
    to_status: Status
    principal_id: PrincipalId


def _require_project(row: EditableMemory, project_id: ProjectId, *, source: str) -> None:
    """Re-assert project scope on every row before acting on it -- the same defensive
    re-check `workers.invalidator`/`workers.sweeps`/`workers.revalidation` all perform on
    their own store reads (invariant 4): a select that returns a foreign-project row is an
    isolation failure, not a row to silently act on."""
    if row.project_id != project_id:
        raise TracebedError(
            f"{source} returned memory {row.id} scoped to project {row.project_id}, not "
            f"the requested {project_id} (invariant 4)"
        )


class EditOps:
    """The four operator edit operations. `repo` is this module's own
    `MemoryEditRepoPort`; `key_manager` is the crypto-shredding seam
    (`crypto.shred.SubjectKeyManager`) `delete_by_subject` uses for the KEK half of
    erasure."""

    def __init__(self, repo: MemoryEditRepoPort, key_manager: SubjectKeyManager, clock: Clock) -> None:
        self._repo = repo
        self._key_manager = key_manager
        self._clock = clock

    # -- pin ------------------------------------------------------------------------

    def pin(
        self,
        project_id: ProjectId,
        *,
        content: str,
        principal_id: PrincipalId,
        scope_type: ScopeType,
        scope_id: UUID | None,
        cfg: EffectiveConfig,
        kind: str = "preference",
        subject_tag: str | None = None,
    ) -> PinResult:
        """PLAN.md §5 row 3: `None -> pinned`, for preferences only
        (`_guard_none_to_pinned` also requires `mem_type == PREFERENCE`, enforced here by
        never accepting a `mem_type` parameter at all -- there is no other `mem_type`
        this method can produce).

        Goes through `core.scans` like every insert (invariant 6): a rejected scan raises
        `ScanRejected` here, unchanged -- persisting that rejection to `review_queue` is
        the caller's job via `workers.review_queue.ReviewQueue.flag_scan_rejection`
        (mirrors `core.scans.persist_rejection`'s own "the caller's job" contract).

        `token_count` is DERIVED from `content`, never accepted -- see
        `_estimate_token_count` for why a caller-supplied count on this particular memory
        class is a static-prefix budget bypass rather than a convenience.

        `trust_tier`/`lane` have no natural value for a pinned preference
        (D-014: pinned is "the explicit ungoverned status for preferences only", outside
        the Tier A/B distinction `_guard_none_to_pinned` does not even inspect) but both
        columns are `NOT NULL` on `memory_item`. `TrustTier.A`/`Lane.OPERATIONAL` are used
        as the closest fit (a preference needs no corroboration, exactly like Tier A; no
        LLM judge is ever involved, exactly like the operational lane) -- an arbitrary but
        fixed and documented choice, not a magic number smuggled into logic a guard reads.

        `subject_tag` is the erasure handle and it is NOT optional in practice for a
        preference that is about a person: `delete_by_subject` (this same module) finds
        rows exclusively through `memory_item.subject_tag`, so a pinned preference created
        without one is unreachable by the erasure path forever -- content this module
        creates that the module's own erasure operation provably cannot delete. It stays
        `None`-defaulted only because a genuinely subject-less operator preference (an
        environment or project-wide rule) exists and must not be forced to invent a
        subject it does not have.
        """
        ctx = ScanContext(
            project_id=project_id,
            mem_type=MemType.PREFERENCE,
            trust_tier=TrustTier.A,
            provenance_class=ProvenanceClass.OPERATOR,
            lane=Lane.OPERATIONAL,
        )
        result = scan(content, context=ctx)
        verdict = result.verdict(clock=self._clock)  # raises ScanRejected if not passed

        limits = TransitionLimits.from_config(cfg)
        evidence = TransitionEvidence(
            now=self._clock.now(),
            provenance_class=ProvenanceClass.OPERATOR,
            trust_tier=TrustTier.A,
            mem_type=MemType.PREFERENCE,
            operator_created=True,
        )
        new_status = apply(None, Status.PINNED, evidence, limits)

        item = NewMemoryItem(
            scope_type=scope_type,
            scope_id=scope_id,
            mem_type=MemType.PREFERENCE,
            kind=kind,
            lane=Lane.OPERATIONAL,
            trust_tier=TrustTier.A,
            status=new_status,
            content=content,
            token_count=_estimate_token_count(content),
            provenance=Provenance(cls=ProvenanceClass.OPERATOR, principal=principal_id),
            subject_tag=subject_tag,
        )
        memory_id = self._repo.insert_memory_item(project_id, item, verdict)
        return PinResult(memory_id=memory_id, status=new_status)

    # -- delete-by-subject ------------------------------------------------------------

    def delete_by_subject(
        self, project_id: ProjectId, subject_tag: str, *, cfg: EffectiveConfig
    ) -> DeleteBySubjectResult:
        """Crypto-shredding (`SubjectKeyManager.destroy_subject`) plus a tombstone
        transition for every governed memory tagged with this subject
        (`*->tombstoned`, `erasure_or_approved_delete=True`).

        The two effects are independent and both real: destroying the KEK makes every
        trace payload SECTION tagged with this subject permanently unreadable while the
        stored object's BYTES never change (`crypto/shred.py`, already tested there); this
        method's own job is the SEPARATE governed-memory side -- a `memory_item` row
        merely carrying `subject_tag` on its own column, independent of whatever trace
        sections it may or may not still reference.

        Every row the store returned is validated BEFORE any of them is tombstoned. A
        store that hands back a foreign-project or foreign-subject row is an isolation
        failure, and discovering it halfway through the loop would leave an erasure
        half-applied against an unknown-correct row set -- the refusal has to come before
        the first write, not from inside it.

        KEK destruction happens first and unconditionally: it is the erasure act that
        must not be blocked by a store defect on the governed-memory side (a subject's
        right to erasure does not wait on `memory_item` being well-formed).
        """
        if not subject_tag:
            raise ValueError("delete_by_subject requires a non-empty subject_tag")

        key_destroyed = self._key_manager.destroy_subject(project_id, subject_tag)
        rows = self._repo.select_by_subject_tag(project_id, subject_tag)
        for row in rows:
            _require_project(row, project_id, source="select_by_subject_tag")
            if row.subject_tag != subject_tag:
                raise TracebedError(
                    f"select_by_subject_tag({subject_tag!r}) returned memory {row.id} "
                    f"tagged {row.subject_tag!r}; a subject-scoped erasure must not act on "
                    f"a row outside the requested subject"
                )

        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)
        tombstoned: list[MemoryId] = []
        already: list[MemoryId] = []
        for row in rows:
            if row.status is Status.TOMBSTONED:
                # `(TOMBSTONED, TOMBSTONED)` is not a legal edge (tombstoned is the one
                # terminal status) -- calling `apply()` on it would raise `IllegalTransition`
                # for a row that is already exactly where erasure wants it. A no-op, not a
                # refusal.
                already.append(row.id)
                continue
            evidence = TransitionEvidence(
                now=now,
                provenance_class=row.provenance.cls,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                status_changed_at=row.status_changed_at,
                erasure_or_approved_delete=True,
            )
            new_status = apply(row.status, Status.TOMBSTONED, evidence, limits)
            self._repo.persist_status(
                project_id,
                MemoryStatusWrite(
                    memory_id=row.id, from_status=row.status, to_status=new_status, now=now
                ),
            )
            tombstoned.append(row.id)

        return DeleteBySubjectResult(
            subject_tag=subject_tag,
            key_destroyed=key_destroyed,
            tombstoned_memory_ids=tuple(tombstoned),
            already_tombstoned_memory_ids=tuple(already),
        )

    # -- merge ------------------------------------------------------------------------

    def merge(
        self, project_id: ProjectId, source_memory_ids: Sequence[MemoryId], *, cfg: EffectiveConfig
    ) -> MergeResult:
        """Supersedes every source (`validated -> superseded`,
        `contradiction_equal_or_stronger=True`) -- an operator's decision to merge is
        definitionally an equal-or-stronger authority over the memories it merges.

        A non-`validated` source is refused by `apply()` itself: `(status, SUPERSEDED)`
        for any `status` other than `VALIDATED` is not in `TRANSITIONS` at all, so
        `IllegalTransition` propagates unchanged -- there is no pre-check here that
        duplicates that refusal.

        ALL-OR-NOTHING. `apply()` is a pure function, so every source can be put through
        the machine before ANY of them is written. Writing as it went meant a refused
        merge still destroyed the sources that happened to come first in the list: the
        operator sees `IllegalTransition`, believes the merge did not happen, and the
        earlier `validated` memories are already `superseded` -- unretrievable, with no
        merged replacement row to take their place (see the module docstring's CONTRACT
        GAP: `merge` never inserts one). That is memory destruction from an operation
        that reported failure, reachable by anyone who can submit a merge batch
        containing one ineligible id.

        Sources must also be DISTINCT ids. `merge(m, m)` cleared the "at least two"
        check, superseded `m`, and then refused `(superseded -> superseded)` -- the same
        destroy-then-report-failure shape, and the merge of a memory with itself is not
        a merge in the first place.
        """
        unique_ids = list(dict.fromkeys(source_memory_ids))
        if len(unique_ids) != len(source_memory_ids):
            raise ValueError("merge sources must be distinct memory ids; a duplicate was given")
        if len(unique_ids) < 2:
            raise ValueError("merge requires at least two source memory ids")

        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)

        resolved: list[tuple[EditableMemory, Status]] = []
        for memory_id in unique_ids:
            row = self._repo.get_memory_by_id(project_id, memory_id)
            _require_project(row, project_id, source="get_memory_by_id")
            evidence = TransitionEvidence(
                now=now,
                provenance_class=row.provenance.cls,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                status_changed_at=row.status_changed_at,
                contradiction_equal_or_stronger=True,
            )
            resolved.append((row, apply(row.status, Status.SUPERSEDED, evidence, limits)))

        # Every source cleared the machine; only now does anything become durable.
        for row, new_status in resolved:
            self._repo.persist_status(
                project_id,
                MemoryStatusWrite(
                    memory_id=row.id, from_status=row.status, to_status=new_status, now=now
                ),
            )
        return MergeResult(superseded_memory_ids=tuple(row.id for row, _ in resolved))

    # -- operator_edit ------------------------------------------------------------------

    def operator_edit(
        self, project_id: ProjectId, memory_id: MemoryId, *, principal_id: PrincipalId, cfg: EffectiveConfig
    ) -> OperatorEditResult:
        """D-032: "supersedes directly (a state-machine transition)" -- see the module
        docstring's CONTRACT GAP note for exactly what this does and does not do.

        Only `validated -> superseded` is attempted; any other current status is refused
        by `apply()` (`IllegalTransition`), matching the other three ops' refusal
        discipline.
        """
        row = self._repo.get_memory_by_id(project_id, memory_id)
        _require_project(row, project_id, source="get_memory_by_id")
        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)
        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
            contradiction_equal_or_stronger=True,
        )
        new_status = apply(row.status, Status.SUPERSEDED, evidence, limits)
        self._repo.persist_status(
            project_id,
            MemoryStatusWrite(
                memory_id=memory_id,
                from_status=row.status,
                to_status=new_status,
                now=now,
                actor_principal=principal_id,
            ),
        )
        return OperatorEditResult(
            memory_id=memory_id, from_status=row.status, to_status=new_status, principal_id=principal_id
        )
