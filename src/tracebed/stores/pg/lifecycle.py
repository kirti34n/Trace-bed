"""`LifecycleWriter` — the status-write path (docs/FIDELITY-AUDIT.md §1/§5/§11 finding M1;
PLAN.md §11 M1; hard rule 5).

The audit, verbatim: "There is no `UPDATE memory_item` statement anywhere in `src/`
(`workers/edit_ops.py:204` says so outright) ... promotion, staleness, two-strike
retirement, archiving, pinning and crypto-shred tombstoning are all COMPUTED CORRECTLY and
NONE can be saved." `domain.state_machine.apply()` has always been correct; nothing has
ever called an `UPDATE` after it returned. This module is that missing call.

`persist_status` satisfies the ONE shape two Protocols already declare and this chunk may
not redefine (`workers.edit_ops.MemoryEditRepoPort.persist_status`,
`workers.forensics.ForensicsRepoPort.persist_status` — both
``def persist_status(self, project_id: ProjectId, write: MemoryStatusWrite) -> None``,
character for character identical, and a third caller, `workers.preferences`, uses the same
two-positional-argument call shape without declaring its own Protocol at all).

CONTRACT GAP (reported, not deviated from): the task that spawned this chunk described a
richer signature —
``persist_status(project_id, memory_id, *, expected_from, to, evidence, reason, actor)`` —
matching a design where this method calls `state_machine.apply()` itself. The two Protocols
actually declared in the codebase (read, per instruction, in preference to that paraphrase)
take `MemoryStatusWrite` instead, and `MemoryStatusWrite` (`workers/edit_ops.py`) carries
only `memory_id`, `from_status`, `to_status`, `now`, and an optional `actor_principal` — no
`TransitionEvidence`, no `reason`. That is because all three existing callers already run
`apply()` themselves, against evidence only they hold (a freshly-read `EditableMemory` row's
`provenance`/`trust_tier`/`mem_type`/`status_changed_at` plus per-call guard flags), and pass
this module only `apply()`'s *result* — never fabricate a `TransitionEvidence` to satisfy a
guard second-hand; a guard evaluated against invented evidence is exactly the "second way to
decide a status" hard rule 5 forbids, even if it happens to agree with the truth this time.

What this module verifies instead, with the arguments it actually receives, is the
strongest check the real contract supports: `(write.from_status, write.to_status)` must be a
real edge in `state_machine.TRANSITIONS` — the same table `apply()` itself consults before
running any guard. A `MemoryStatusWrite` built by hand for an edge that was NEVER legal
(`quarantined -> validated` directly, or anything at all off `tombstoned`, which has no
outgoing edge — `_TRANSITIONS` never contains a `(TOMBSTONED, *)` key, TOMBSTONED being the
one terminal status) is refused before a single SQL statement is issued. This does not
re-run the guard's own conditions (shadow-confirm count, TTL, Q threshold, ...) a second
time — only the one `apply()` call the caller already made decided those, and this module
has no evidence to decide them again. `persist_status` additionally accepts optional
`guard_evidence`/`guard_limits` keyword arguments (both or neither): a future caller with
evidence to spare can request a full second `apply()` pass, and this module runs it before
writing anything.

Non-negotiable properties (verified by `tests/phase3/test_status_persistence.py`):

  (a) A structurally illegal `(from_status, to_status)` pair — or a supplied
      `guard_evidence`/`guard_limits` pair `apply()` itself refuses — raises before `scoped()`
      is ever entered. Zero SQL statements issued on refusal.
  (b) The UPDATE's WHERE clause is `project_id = %(project_id)s AND id = %(memory_id)s AND
      status = %(expected_from)s`. Zero rows affected means a concurrent writer already
      moved this row (two sweeps racing on the same memory is the normal case, not the
      exotic one — PLAN.md §7 Phase 2/3 runs `revalidation`, `sweeps`, and the kill switch
      as independent, overlapping passes) — raises `StaleStatusTransition` rather than
      overwriting whatever is there now.
  (c) `status_changed_at` is `write.now`, which `MemoryStatusWrite.__post_init__` already
      refuses to accept naive (hard rule 3: no `datetime.now()` here either — `write.now`
      came from the caller's injected `Clock`, and this module reads no clock of its own).
  (d) Terminal statuses are terminal: `write.from_status is Status.TOMBSTONED` can never
      reach the UPDATE at all, because no `(TOMBSTONED, *)` edge exists in `TRANSITIONS` —
      the check in (a) already refuses it. There is no separate tombstone-specific check
      because none is needed; a second one would be redundant, not stronger.

The status UPDATE and the `memory_status_log` INSERT run on the SAME connection inside
`stores.pg.pool.scoped()`'s one transaction (PostgreSQL wraps every multi-statement session
in an implicit transaction unless autocommit is on, and `scoped()` explicitly opens one via
`conn.transaction()`) — a status change with no history row is exactly the audit-trail gap
`docs/FIDELITY-AUDIT.md` §4.1 keeps finding in this repository's own documents; committing
the UPDATE without the INSERT (or vice versa) would just relocate it into this file.

CONTRACT GAP — CLOSED in the integration pass (D-128). `migrations/0004_lifecycle.sql`
creates `memory_status_log` as an empty partitioned parent, matching every other
learning-plane table's own migration; `stores/pg/ddl.py`'s `PARTITIONED_TABLES` now names it
(14th entry) with an index on `(memory_id, changed_at DESC)`, so
`stores.pg.partitions.create_project_partitions` gives every project a partition and the
history INSERT below no longer fails with "no partition of relation found for row". The
table was also RENAMED from `memory_status_history` while closing that gap, for a reason worth
recording where a reader will meet it: at 21 characters the old name made
`ddl.partition_policy_name` emit `memory_status_history_p_<32 hex>_isolation` (66 bytes),
over PostgreSQL's 63-byte identifier limit, so `create_project_partitions` raised for EVERY
project — the status writer would have been dead on arrival in any real deployment while
passing every offline test that never built the policy name.

STILL OPEN, and this module inherits rather than closes it: `memory_status_log.epoch_id` and
`memory_item.epoch_id` have no writer. `persist_status` accepts `epoch_id` as an optional
keyword and every caller today leaves it `None`, so the "which scoring epoch was this
transition decided under" column is present, typed, and empty. Closing it belongs to
whichever pass implements `ScorerRepoPort`/`EpochStorePort` (PLAN.md §11 M3).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from psycopg.rows import DictRow, dict_row
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

from tracebed.domain.clock import Clock
from tracebed.domain.errors import IllegalTransition, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import NewMemoryItem
from tracebed.domain.scan import ScanVerdict
from tracebed.domain.state_machine import (
    TRANSITIONS,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
)
from tracebed.stores.pg.pool import scoped
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.rows import MemoryItemRow
from tracebed.workers.edit_ops import EditableMemory, MemoryStatusWrite
from tracebed.workers.forensics import OutcomeEventRef

__all__ = [
    "ForensicsRepo",
    "LifecycleWriter",
    "MemoryEditRepo",
    "StaleStatusTransition",
]


class StaleStatusTransition(TracebedError):
    """Optimistic-concurrency loss on `memory_item.status` (non-negotiable property (b)).

    CONTRACT GAP (reported, not deviated from): `domain/errors.py` is this repository's one
    exception-hierarchy module and every other typed error in this file's neighbourhood
    derives from `TracebedError` there — this class belongs beside `IllegalTransition` /
    `GuardNotSatisfied`, not here. `domain/errors.py` is not in this chunk's file list, so it
    is defined locally, deriving from `TracebedError` for the same uniform-catch behaviour
    (`api/main.py`'s single exception handler, §9.4) every other typed error gets.
    """

    def __init__(
        self, project_id: ProjectId, memory_id: MemoryId, *, expected_from: Status, to: Status
    ) -> None:
        super().__init__(
            f"memory {memory_id} in project {project_id} is no longer {expected_from.value!r}; "
            f"a concurrent writer moved it before this {expected_from.value!r} -> "
            f"{to.value!r} transition could be persisted"
        )
        self.project_id = project_id
        self.memory_id = memory_id
        self.expected_from = expected_from
        self.to = to


_UPDATE_STATUS_SQL = """
    UPDATE memory_item
       SET status = %(to_status)s, status_changed_at = %(changed_at)s
     WHERE project_id = %(project_id)s AND id = %(memory_id)s AND status = %(expected_from)s
"""

_INSERT_HISTORY_SQL = """
    INSERT INTO memory_status_log (
        project_id, memory_id, from_status, to_status, reason, actor, evidence, epoch_id,
        changed_at
    ) VALUES (
        %(project_id)s, %(memory_id)s, %(from_status)s, %(to_status)s, %(reason)s, %(actor)s,
        %(evidence)s, %(epoch_id)s, %(changed_at)s
    )
"""


class LifecycleWriter:
    """`LifecycleWriter(pool, clock)`. `clock` is taken (hard rule 3) even though the
    current code path never calls it: `write.now` is always the caller's own clock read, and
    an injected clock here is what keeps that true if a future revision ever needs "when did
    THIS module act" as a distinct instant from "when did the transition happen"."""

    def __init__(self, pool: ConnectionPool, clock: Clock) -> None:
        self._pool = pool
        self._clock = clock

    def persist_status(
        self,
        project_id: ProjectId,
        write: MemoryStatusWrite,
        *,
        reason: str = "",
        evidence: Mapping[str, Any] | None = None,
        epoch_id: int | None = None,
        guard_evidence: TransitionEvidence | None = None,
        guard_limits: TransitionLimits | None = None,
    ) -> None:
        """Persist the transition `write` describes. Raises (issuing zero SQL) if it is not
        one `state_machine.TRANSITIONS` recognises, or if the caller opts into full guard
        reverification (`guard_evidence` + `guard_limits`) and `apply()` refuses it. Raises
        `StaleStatusTransition` (module docstring, property (b)) if the row already moved.

        `reason`/`evidence`/`epoch_id` land on the `memory_status_log` row this call
        writes; none of the three real callers today supply them (see module docstring),
        so they default to the empty string / `{}` / `NULL` rather than being required.
        """
        self._authorize(write, guard_evidence, guard_limits)

        with scoped(self._pool, project_id) as conn:
            cur = conn.execute(
                _UPDATE_STATUS_SQL,
                {
                    "to_status": write.to_status.value,
                    "changed_at": write.now,
                    "project_id": project_id,
                    "memory_id": write.memory_id,
                    "expected_from": write.from_status.value,
                },
            )
            if cur.rowcount == 0:
                # Nothing has been committed by this transaction (`scoped()` opens exactly
                # one, `conn.transaction()`'s context manager rolls back on the exception
                # this raises), so there is no half-applied write to clean up.
                raise StaleStatusTransition(
                    project_id,
                    write.memory_id,
                    expected_from=write.from_status,
                    to=write.to_status,
                )
            conn.execute(
                _INSERT_HISTORY_SQL,
                {
                    "project_id": project_id,
                    "memory_id": write.memory_id,
                    "from_status": write.from_status.value,
                    "to_status": write.to_status.value,
                    "reason": reason,
                    "actor": write.actor_principal,
                    "evidence": Json(dict(evidence) if evidence is not None else {}),
                    "epoch_id": epoch_id,
                    "changed_at": write.now,
                },
            )

    @staticmethod
    def _authorize(
        write: MemoryStatusWrite,
        guard_evidence: TransitionEvidence | None,
        guard_limits: TransitionLimits | None,
    ) -> None:
        """The whole of non-negotiable property (a). Pure -- no store, no clock, no I/O --
        so every caller this raises for issues no SQL at all (module docstring)."""
        if (guard_evidence is None) != (guard_limits is None):
            raise ValueError(
                "LifecycleWriter.persist_status: guard_evidence and guard_limits must be "
                "given together or not at all -- a partial guard reverification verifies "
                "nothing"
            )
        if guard_evidence is not None and guard_limits is not None:
            # Full reverification for a caller that has evidence to spare. `apply()` raises
            # `IllegalTransition`/`GuardNotSatisfied` itself on refusal -- propagated
            # unchanged, exactly like `workers.edit_ops`/`workers.forensics` never catch
            # their own `apply()` call either.
            apply(write.from_status, write.to_status, guard_evidence, guard_limits)
            return
        # The structural floor every caller gets even with no evidence at all: the edge
        # itself must be one `apply()` could ever have approved. `TRANSITIONS` has no
        # `(Status.TOMBSTONED, *)` key for any status (TOMBSTONED is the sole terminal
        # status, PLAN.md §5), so this is also the entirety of non-negotiable property (d) --
        # a from_status of TOMBSTONED fails this membership test for every possible
        # to_status, with no further tombstone-specific code needed.
        if (write.from_status, write.to_status) not in TRANSITIONS:
            raise IllegalTransition(write.from_status, write.to_status)


# --------------------------------------------------------------------------- #
# The two repository ports whose only implementations were test fakes
# (FIDELITY-AUDIT.md M1/M3; PLAN.md 11.1). Added in the integration pass that
# wired the learning plane, not by the chunk that wrote `LifecycleWriter`.
# --------------------------------------------------------------------------- #

_SELECT_BY_SUBJECT_TAG_SQL: Final[str] = """
SELECT id, project_id, status, trust_tier, mem_type, provenance, status_changed_at, subject_tag
FROM memory_item
WHERE project_id = %(project_id)s AND subject_tag = %(subject_tag)s
ORDER BY id
""".strip()

_RUNS_INJECTED_WITH_SQL: Final[str] = """
SELECT DISTINCT run_id
FROM injection_log
WHERE project_id = %(project_id)s AND memory_id = %(memory_id)s
ORDER BY run_id
""".strip()

_DIRECT_DERIVED_DESCENDANTS_SQL: Final[str] = """
SELECT src_id
FROM memory_link
WHERE project_id = %(project_id)s AND dst_id = %(memory_id)s AND relation = 'derived_from'
ORDER BY src_id
""".strip()

_OUTCOME_EVENTS_FOR_RUNS_SQL: Final[str] = """
SELECT event_id, run_id
FROM outcome_event
WHERE project_id = %(project_id)s AND run_id = ANY(%(run_ids)s)
ORDER BY event_id
""".strip()


def _to_editable(row: MemoryItemRow) -> EditableMemory:
    """`MemoryItemRow` -> `EditableMemory`. Exactly the "projection adapter, not a new query"
    `MemoryEditRepoPort.get_memory_by_id`'s own docstring predicted would be enough."""
    return EditableMemory(
        id=row.id,
        project_id=row.project_id,
        status=row.status,
        trust_tier=row.trust_tier,
        mem_type=row.mem_type,
        provenance=row.provenance,
        status_changed_at=row.status_changed_at,
        subject_tag=row.subject_tag,
    )


def _dict_to_editable(row: DictRow) -> EditableMemory:
    """Same projection from a raw row. `select_by_subject_tag` selects only the eight columns
    `EditableMemory` carries rather than reusing `Repo`'s wider `_MEMORY_ITEM_COLUMNS`: an
    erasure path should not pull `content` for every matching row into this process's memory."""
    from tracebed.domain.enums import MemType, TrustTier
    from tracebed.domain.memory import Provenance

    return EditableMemory(
        id=MemoryId(row["id"]),
        project_id=ProjectId(row["project_id"]),
        status=Status(row["status"]),
        trust_tier=TrustTier(row["trust_tier"]),
        mem_type=MemType(row["mem_type"]),
        provenance=Provenance.from_json(row["provenance"]),
        status_changed_at=row["status_changed_at"],
        subject_tag=row["subject_tag"],
    )


class MemoryEditRepo:
    """`workers.edit_ops.MemoryEditRepoPort` over Postgres -- and, structurally, the port
    `workers.preferences.PreferenceManager` takes as well (that module imports
    `MemoryEditRepoPort` rather than declaring its own).

    COMPOSES rather than reimplements: `get_memory_by_id` and `insert_memory_item` delegate to
    the real `Repo` (whose own port docstring already said "a real `Repo` needs only a
    projection adapter, not a new query"), and `persist_status` delegates to `LifecycleWriter`
    so there is exactly ONE `UPDATE memory_item SET status` statement in `src/`. A second copy
    here would be a second way to write a status, which is the admin bypass PLAN.md section 10
    forbids wearing a repository's clothes.

    Only `select_by_subject_tag` is new SQL, because it was the one method with no `Repo`
    equivalent -- its port docstring said so: "CONTRACT GAP: `Repo` has no query indexed on
    `memory_item.subject_tag` today".
    """

    def __init__(self, pool: ConnectionPool, repo: Repo, lifecycle: LifecycleWriter) -> None:
        self._pool = pool
        self._repo = repo
        self._lifecycle = lifecycle

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> EditableMemory:
        return _to_editable(self._repo.get_memory_by_id(project_id, memory_id))

    def select_by_subject_tag(
        self, project_id: ProjectId, subject_tag: str
    ) -> Sequence[EditableMemory]:
        """Every memory carrying this subject tag, for `EditOps.delete_by_subject` (the
        crypto-shred path). `subject_tag` is a bound parameter, never interpolated: it is the
        one value on this method derived from caller-supplied data.

        `stores.pg.ddl`'s `memory_item` partition carries a btree on `subject_tag`, so this is
        an index scan rather than the partition scan an erasure request must not become.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _SELECT_BY_SUBJECT_TAG_SQL,
                {"project_id": project_id, "subject_tag": subject_tag},
            )
            rows = cur.fetchall()
        return [_require_scoped(_dict_to_editable(row), project_id) for row in rows]

    def persist_status(self, project_id: ProjectId, write: MemoryStatusWrite) -> None:
        self._lifecycle.persist_status(project_id, write)

    def insert_memory_item(
        self, project_id: ProjectId, item: NewMemoryItem, scan_verdict: ScanVerdict
    ) -> MemoryId:
        return self._repo.insert_memory_item(project_id, item, scan_verdict)


class ForensicsRepo:
    """`workers.forensics.ForensicsRepoPort` over Postgres -- Recall & Rollback's store half.

    The three reads beyond `MemoryEditRepo`'s pair are one statement each and deliberately
    ONE HOP only: `list_direct_derived_descendants` returns immediate children, and the
    transitive closure is `Forensics._transitive_descendants`' BFS over repeated calls. That
    split is the port's own instruction, and the reason is worth restating where the SQL lives
    -- a recursive CTE here would make the depth bound invisible to the worker that is supposed
    to enforce it, and the gate test's third-generation assertion exists precisely to catch a
    one-hop implementation pretending to be a closure.
    """

    def __init__(self, pool: ConnectionPool, repo: Repo, lifecycle: LifecycleWriter) -> None:
        self._pool = pool
        self._repo = repo
        self._lifecycle = lifecycle

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> EditableMemory:
        return _to_editable(self._repo.get_memory_by_id(project_id, memory_id))

    def persist_status(self, project_id: ProjectId, write: MemoryStatusWrite) -> None:
        self._lifecycle.persist_status(project_id, write)

    def list_runs_injected_with(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> Sequence[RunId]:
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _RUNS_INJECTED_WITH_SQL, {"project_id": project_id, "memory_id": memory_id}
            )
            rows = cur.fetchall()
        return [RunId(row["run_id"]) for row in rows]

    def list_direct_derived_descendants(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> Sequence[MemoryId]:
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _DIRECT_DERIVED_DESCENDANTS_SQL,
                {"project_id": project_id, "memory_id": memory_id},
            )
            rows = cur.fetchall()
        return [MemoryId(row["src_id"]) for row in rows]

    def list_outcome_events_for_runs(
        self, project_id: ProjectId, run_ids: Sequence[RunId]
    ) -> Sequence[OutcomeEventRef]:
        """An empty `run_ids` returns `[]` without issuing a statement -- `= ANY('{}')` matches
        nothing, so the query is pure cost, and a blast radius over zero runs is a legitimate
        (if uninteresting) call from `Forensics` on a memory that was never injected."""
        if not run_ids:
            return []
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _OUTCOME_EVENTS_FOR_RUNS_SQL,
                {"project_id": project_id, "run_ids": [r.value for r in run_ids]},
            )
            rows = cur.fetchall()
        return [
            OutcomeEventRef(event_id=row["event_id"], run_id=RunId(row["run_id"]))
            for row in rows
        ]


def _require_scoped(row: EditableMemory, project_id: ProjectId) -> EditableMemory:
    """The SQL predicate is the control; this is the assertion the control held.

    Same discipline as `stores.pg.search._row_to_arm_hit` and
    `stores.pg.learning._row_to_embedding_candidate`. It matters more here than on most reads:
    `select_by_subject_tag` feeds `EditOps.delete_by_subject`, so a row that crossed the project
    wall would be a memory this caller is about to tombstone and crypto-shred.
    """
    if row.project_id != project_id:  # pragma: no cover - RLS + predicate both hold
        raise TracebedError(
            f"select_by_subject_tag for project {project_id} returned memory {row.id} "
            f"belonging to project {row.project_id} -- invariant 4"
        )
    return row
