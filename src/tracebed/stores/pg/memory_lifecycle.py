"""`MemoryLifecycleRepo` — the ONE Postgres store behind `MemoryLifecycleRepoPort`.

`workers.invalidator.MemoryLifecycleRepoPort` is a single `@runtime_checkable` Protocol shared,
imported verbatim, by three Phase 2 lifecycle workers: `workers.invalidator.Invalidator`,
`workers.revalidation.RevalidationWorker`, and the `workers.sweeps` functions. Each was validated
offline against its own in-memory `_FakeRepo`; this module is the single implementation whose
observable behaviour must match the *union* of all three fakes, method for method (the
fake-fidelity contract). Nothing but the test fakes implemented this port before.

WHY A NEW STORE RATHER THAN A `Repo` METHOD (contract gap, reported by `workers.invalidator`'s
own module docstring): `Repo.list_memories` is the closest existing read, but it returns
`stores.pg.rows.MemoryItemRow`, which carries neither `last_retrieved_at` nor the smaller
governance-only projection these workers need, and there is no `Repo` write path for a
`memory_item` status/strike/q_value change at all. This port defines exactly what the three
workers need; `repo.py` is outside this chunk's file list, so the projection and the write live
here instead.

WHY `persist` WRITES ITS OWN SQL RATHER THAN DELEGATING TO `LifecycleWriter.persist_status`
(PLAN §10's single-status-UPDATE rule, and the one documented exception to it): the union of the
three fakes' `persist` contracts is WIDER than `persist_status` can express — it conditionally
touches `strike_count` / `q_value` / `last_revalidated_at`, and it must NOT touch
`status_changed_at` on a `from_status == to_status` field touch (a reflexive "nothing changed"
write that `persist_status` cannot represent because it always sets `status_changed_at` and
rejects `from == to` as an illegal edge). Convention 7 names `memory_lifecycle.py` as the sole
store permitted to emit its own `UPDATE memory_item SET status`.

DELIBERATE SCOPE DECISION — `persist` writes NO `memory_status_log` row. The three fakes the
workers were validated against record no history, no worker or test reads it back through this
port, and a reflexive field touch is not a status transition to log. Appending history for these
lifecycle transitions (with the `reason`/`epoch_id` semantics `LifecycleWriter` leaves open) is a
cross-cutting audit-trail decision for the integration pass, not a fake-mirrored behaviour this
store may invent. Reported in the handoff notes rather than silently added.

Isolation (invariant 4): every method takes its connection through `stores.pg.pool.scoped`, which
sets the `tracebed.project_id` RLS GUC as the transaction's first statement, AND carries an
explicit `project_id = %(project_id)s` predicate in every statement (the primary control and the
LIST-partition pruning key; RLS FORCE is the backstop). Every returned row is re-asserted through
`_require_scoped` — the belt-and-braces that turns any hypothetical control failure into a loud
raise, never a silent cross-project leak.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Final

from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.enums import MemType, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.lifecycle import StaleStatusTransition
from tracebed.stores.pg.pool import scoped
from tracebed.workers.invalidator import LifecycleMemoryRow, LifecycleTransitionWrite

__all__ = ["MemoryLifecycleRepo"]


# The governance-only projection these workers need (contract §5.2 shape, minus `content`, plus
# `last_retrieved_at` / `q_value`). Listed literally in each template so no f-string is needed
# (ruff S608) and no `.replace()` placeholder guard is required.
_COLUMNS: Final[str] = (
    "id, project_id, status, trust_tier, mem_type, provenance, "
    "status_changed_at, strike_count, last_retrieved_at, created_at, q_value"
)

# select_by_provenance — UNION (not intersection) over the three selector fields, via the jsonb
# `?|` overlap operator. An empty selector array yields `?| '{}'` -> false, and a memory lacking a
# provenance key yields `NULL ?| ...` -> NULL -> false in the WHERE, so a single static template
# covers all-empty, one-field, and all-three cases without any dynamic clause building. The three
# array binds are cast to text[] so an empty list is still unambiguously typed.
_SELECT_BY_PROVENANCE_SQL: Final[str] = """
SELECT id, project_id, status, trust_tier, mem_type, provenance,
       status_changed_at, strike_count, last_retrieved_at, created_at, q_value
FROM memory_item
WHERE project_id = %(project_id)s
  AND (
      provenance->'tool_refs' ?| %(tool_refs)s::text[]
      OR provenance->'trace_ids' ?| %(trace_ids)s::text[]
      OR provenance->'input_sig_hashes' ?| %(input_sig_hashes)s::text[]
  )
ORDER BY id
""".strip()

# select_by_status — the indexed (project_id, status) query the port docstring requires; ORDER BY
# id only for a deterministic result, never a trace-store touch.
_SELECT_BY_STATUS_SQL: Final[str] = """
SELECT id, project_id, status, trust_tier, mem_type, provenance,
       status_changed_at, strike_count, last_retrieved_at, created_at, q_value
FROM memory_item
WHERE project_id = %(project_id)s AND status = ANY(%(statuses)s)
ORDER BY id
LIMIT %(limit)s
""".strip()

# select_due_for_revalidation — validated rows whose idle reference (last_retrieved_at, or
# created_at if never retrieved) is at or BEFORE (inclusive `<=`) older_than.
_SELECT_DUE_SQL: Final[str] = """
SELECT id, project_id, status, trust_tier, mem_type, provenance,
       status_changed_at, strike_count, last_retrieved_at, created_at, q_value
FROM memory_item
WHERE project_id = %(project_id)s
  AND status = %(validated)s
  AND COALESCE(last_retrieved_at, created_at) <= %(older_than)s
ORDER BY id
LIMIT %(limit)s
""".strip()

# persist — the wider SET clause (convention 7). `status` is always assigned (a field touch's
# to_status == from_status, so it is a no-op); `status_changed_at` moves to `now` ONLY on a real
# transition (from != to); strike_count / q_value / last_revalidated_at are touched only when the
# write carries a non-None value (COALESCE(new, old) leaves the column alone when new is NULL).
# The WHERE is the optimistic-concurrency guard: zero rows means the row moved (or is another
# project's) -> StaleStatusTransition, never a blind overwrite.
_PERSIST_SQL: Final[str] = """
UPDATE memory_item
   SET status = %(to_status)s,
       status_changed_at = CASE
           WHEN %(from_status)s = %(to_status)s THEN status_changed_at
           ELSE %(now)s::timestamptz
       END,
       strike_count = COALESCE(%(strike_count)s::integer, strike_count),
       q_value = COALESCE(%(q_value)s::double precision, q_value),
       last_revalidated_at = COALESCE(%(last_revalidated_at)s::timestamptz, last_revalidated_at)
 WHERE project_id = %(project_id)s
   AND id = %(memory_id)s
   AND status = %(expected_from)s
""".strip()


def _row_to_lifecycle_row(row: DictRow) -> LifecycleMemoryRow:
    """The one place a `memory_item` DB row becomes a `LifecycleMemoryRow`.

    Mirrors `repo._row_to_memory_item` / `lifecycle._dict_to_editable`: `provenance` rehydrates
    through `Provenance.from_json` (the same jsonb shape `to_json` wrote), the enum columns map
    through their `StrEnum`s, and the timestamps arrive tz-aware from `timestamptz` columns (so
    `LifecycleMemoryRow.__post_init__`'s naive-datetime refusal never fires on a real row).
    """
    return LifecycleMemoryRow(
        id=MemoryId(row["id"]),
        project_id=ProjectId(row["project_id"]),
        status=Status(row["status"]),
        trust_tier=TrustTier(row["trust_tier"]),
        mem_type=MemType(row["mem_type"]),
        provenance=Provenance.from_json(row["provenance"]),
        status_changed_at=row["status_changed_at"],
        strike_count=row["strike_count"],
        last_retrieved_at=row["last_retrieved_at"],
        created_at=row["created_at"],
        q_value=row["q_value"],
    )


def _require_scoped(row: LifecycleMemoryRow, project_id: ProjectId) -> LifecycleMemoryRow:
    """The SQL predicate + RLS are the controls; this asserts they held, on every returned row.

    Same discipline as `lifecycle._require_scoped` / `learning._row_to_embedding_candidate`. It
    matters here because all three consuming workers RAISE (never skip) on a foreign-project row —
    a leak reaching `check_stale` is another project's memory retired by this project's verifier —
    so surfacing it as a loud raise at the store boundary too is strictly belt-and-braces.
    """
    if row.project_id != project_id:  # pragma: no cover - RLS + predicate both hold
        raise TracebedError(
            f"MemoryLifecycleRepo returned memory {row.id} belonging to project "
            f"{row.project_id}, not the requested {project_id} (invariant 4)"
        )
    return row


class MemoryLifecycleRepo:
    """`MemoryLifecycleRepoPort` over Postgres — serves Invalidator, RevalidationWorker, and the
    sweep functions from one implementation (see module docstring). Constructed with the shared
    pool; holds no per-request state."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        """Every row whose provenance overlaps ANY of the three selector fields (union).

        The selector values are encoded to match `Provenance.to_json`'s on-disk form: `tool_refs`
        as-is, `trace_ids` as their string ids, `input_sig_hashes` as lowercase hex — so a bound
        selector and a stored provenance entry are the same string.
        """
        params: dict[str, Any] = {
            "project_id": project_id,
            "tool_refs": list(tool_refs),
            "trace_ids": [str(r) for r in trace_ids],
            "input_sig_hashes": [h.hex() for h in input_sig_hashes],
        }
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_SELECT_BY_PROVENANCE_SQL, params)
            rows = cur.fetchall()
        return [_require_scoped(_row_to_lifecycle_row(r), project_id) for r in rows]

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        """Indexed `(project_id, status)` read. `statuses=[]` returns nothing without a query
        (`= ANY('{}')` matches no row; issuing it would be pure cost)."""
        if not statuses:
            return []
        params = {
            "project_id": project_id,
            "statuses": [s.value for s in statuses],
            "limit": max(0, limit),
        }
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_SELECT_BY_STATUS_SQL, params)
            rows = cur.fetchall()
        return [
            _require_scoped_status(_row_to_lifecycle_row(r), project_id, statuses) for r in rows
        ]

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        """`validated` rows whose idle reference is at or before `older_than` (inclusive)."""
        params = {
            "project_id": project_id,
            "validated": Status.VALIDATED.value,
            "older_than": older_than,
            "limit": max(0, limit),
        }
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_SELECT_DUE_SQL, params)
            rows = cur.fetchall()
        return [
            _require_scoped_status(_row_to_lifecycle_row(r), project_id, [Status.VALIDATED])
            for r in rows
        ]

    def persist(self, project_id: ProjectId, write: LifecycleTransitionWrite) -> None:
        """Writes exactly the fields `write` carries (see module docstring / port docstring).

        Raises `StaleStatusTransition` if the optimistic-concurrency WHERE matches zero rows — a
        concurrent writer already moved the row, or the write targets a row outside `project_id`
        (the isolation acceptance case: `persist(B, write_for_A_id)` mutates nothing and raises).
        """
        params = {
            "project_id": project_id,
            "memory_id": write.memory_id,
            "expected_from": write.from_status.value,
            "from_status": write.from_status.value,
            "to_status": write.to_status.value,
            "now": write.now,
            "strike_count": write.strike_count,
            "q_value": write.q_value,
            "last_revalidated_at": write.last_revalidated_at,
        }
        with scoped(self._pool, project_id) as conn:
            cur = conn.execute(_PERSIST_SQL, params)
            if cur.rowcount == 0:
                # Nothing committed yet (scoped() opens exactly one transaction, rolled back by
                # the exception) — no half-applied write to clean up.
                raise StaleStatusTransition(
                    project_id,
                    write.memory_id,
                    expected_from=write.from_status,
                    to=write.to_status,
                )


def _require_scoped_status(
    row: LifecycleMemoryRow, project_id: ProjectId, statuses: Sequence[Status]
) -> LifecycleMemoryRow:
    """`_require_scoped` plus the status post-condition the two status-predicated reads promise.

    `select_by_status` / `select_due_for_revalidation` feed bulk status CHANGES in the sweeps and
    revalidation workers; a row returned off the requested status set is a control that has
    stopped holding, so it is a loud raise here as well as in each worker's own re-assertion.
    """
    _require_scoped(row, project_id)
    if row.status not in statuses:  # pragma: no cover - the status predicate holds
        wanted = ", ".join(s.value for s in statuses)
        raise TracebedError(
            f"MemoryLifecycleRepo returned memory {row.id} with status {row.status.value!r}, "
            f"not one of the requested [{wanted}] (a status predicate has stopped holding)"
        )
    return row
