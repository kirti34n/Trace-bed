"""Postgres implementation of `workers.shadow_validator.ShadowValidatorRepoPort` —
the JUDGMENT half of shadow validation (`quarantined -> candidate`).

The EVIDENCE half (`CorroborationRepoPort`, which appends `shadow_confirm_runs`) is already
live in `stores.pg.learning.CorroborationRepo`; this module is the missing judgment writer
`harness/phase3_gate.py` and `harness/closed_loop.py` both name as having "NO Postgres impl".

WHY A SEPARATE CLASS. `ShadowValidatorRepoPort.select_quarantined` collides by NAME with
`CorroborationRepoPort.select_quarantined` but returns a DIFFERENT type
(`QuarantinedMemoryRow` vs `QuarantinedMemoryForCorroboration`): the corroboration writer is
deliberately NOT handed `trust_tier`/`mem_type`/`is_failure_lesson`/`status_changed_at`,
because it never judges an edge. One object cannot satisfy both under one name, so this is a
class of its own rather than a second method on `CorroborationRepo` — exactly the split the
harness makes with `_ShadowRepoView`.

TWO HALVES, BOTH COMPOSED FROM EXISTING TEMPLATES.

READ (`select_quarantined`) mirrors `stores.pg.learning.CorroborationRepo` method-for-method:
same table, same `(project_id, status='quarantined')` index+partition-pruned predicate, same
`scoped()` + `dict_row` + fail-loud row parser that refuses any status the predicate should
have excluded. The only difference is a WIDER projection — `trust_tier`, `mem_type`,
`status_changed_at`, and the resolution of `is_failure_lesson` (see below).

WRITE (`persist`) DELEGATES to `stores.pg.lifecycle.LifecycleWriter.persist_status`, exactly
as `MemoryEditRepo`/`ForensicsRepo` do, so there is still exactly ONE `UPDATE memory_item SET
status` statement in `src/` (a second copy is the admin bypass PLAN.md §10 forbids). That one
delegation buys, for free, everything the fake's `persist` promises and more: the structural
edge check (`quarantined -> candidate` is in `TRANSITIONS`), the gated UPDATE + the
`memory_status_log` INSERT in ONE `scoped()` transaction, `StaleStatusTransition` on rowcount 0
(the Postgres analog of the `_Vault` fake's "stale transition" raise), and `epoch_id` landing
on the history row (`ShadowTransitionWrite.epoch_id`, stamped for cross-epoch rejection —
PLAN.md §5). A cross-project write cannot even reach a row: the gated WHERE matches zero rows
under RLS + the predicate, so it raises rather than crossing the wall.

`is_failure_lesson` HAS NO BACKING COLUMN (reported, not invented). The fail-safe default is
`false`: it keeps the STRICTER 2-confirmation bar and never wrongly grants the failure-lesson
relaxation down to 1, matching the fake's `_Row.is_failure_lesson` default. It is deliberately
NOT derived from the untrusted `kind` string — a threshold downgrade on attacker-chosen data —
which is why the SELECT hard-codes `false` rather than reading `kind`. A proper trusted column
is the real fix and belongs to a future migration (RISK 3).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.enums import MemType, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.lifecycle import LifecycleWriter
from tracebed.stores.pg.pool import scoped
from tracebed.workers.edit_ops import MemoryStatusWrite
from tracebed.workers.shadow_validator import QuarantinedMemoryRow, ShadowTransitionWrite

__all__ = ["ShadowValidatorRepo"]


# Widens `CorroborationRepo._SELECT_QUARANTINED_SQL` (which selects only id/project_id/status/
# provenance/shadow_confirm_runs) with the three columns the judgment projection needs plus the
# `is_failure_lesson` resolution. `false AS is_failure_lesson` is the fail-safe default (module
# docstring): the stricter bar, never the untrusted `kind`-derived relaxation. `ORDER BY
# created_at, id` matches the sibling select's deterministic order.
_SELECT_QUARANTINED_SQL: Final[str] = """
SELECT id,
       project_id,
       status,
       trust_tier,
       mem_type,
       provenance,
       status_changed_at,
       false AS is_failure_lesson,
       shadow_confirm_runs
FROM memory_item
WHERE project_id = %(project_id)s AND status = %(quarantined)s
ORDER BY created_at, id
""".strip()


class ShadowValidatorRepo:
    """`workers.shadow_validator.ShadowValidatorRepoPort` over Postgres.

    Satisfies the `runtime_checkable` Protocol structurally (never by inheritance — the
    Protocol lives in `workers/`, and `stores/pg/` importing a worker module for a base class
    would invert the dependency direction). Takes `(pool, lifecycle)` like
    `MemoryEditRepo`/`ForensicsRepo`: the read half uses `pool` directly, the write half
    delegates to `lifecycle` so no second `UPDATE memory_item SET status` is authored here.
    """

    def __init__(self, pool: ConnectionPool, lifecycle: LifecycleWriter) -> None:
        self._pool = pool
        self._lifecycle = lifecycle

    def select_quarantined(self, project_id: ProjectId) -> Sequence[QuarantinedMemoryRow]:
        """Every currently-`quarantined` row for this project, richly projected.

        Indexed `(project_id, status)` — `stores.pg.ddl`'s `memory_item` partition carries a
        btree on `status`, so this is index+partition-pruned, never a trace scan (matching the
        cost discipline `CorroborationRepo.select_quarantined` and `workers.sweeps` keep).
        Returns `[]` (never raises) for a project with no quarantined rows.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _SELECT_QUARANTINED_SQL,
                {"project_id": project_id, "quarantined": Status.QUARANTINED.value},
            )
            rows = cur.fetchall()
        return [_row_to_quarantined_for_validation(row, project_id) for row in rows]

    def persist(self, project_id: ProjectId, write: ShadowTransitionWrite) -> None:
        """Persist the one committed `quarantined -> candidate` transition.

        Delegates to `LifecycleWriter.persist_status` (the single status-write surface in
        `src/`). That call: refuses a structurally illegal edge before any SQL; issues the
        gated UPDATE + the `memory_status_log` INSERT in one `scoped()` transaction; raises
        `StaleStatusTransition` (a `TracebedError`, matching the `_Vault` fake's "stale
        transition" raise) if the row already moved; and records `write.epoch_id` on the
        history row. It does NOT decide the status — `state_machine.apply()` already did in the
        worker; this only writes the approved transition (PLAN.md §10, no admin bypass).
        """
        status_write = MemoryStatusWrite(
            memory_id=write.memory_id,
            from_status=write.from_status,
            to_status=write.to_status,
            now=write.now,
            actor_principal=None,
        )
        self._lifecycle.persist_status(project_id, status_write, epoch_id=write.epoch_id)


def _row_to_quarantined_for_validation(
    row: DictRow, project_id: ProjectId
) -> QuarantinedMemoryRow:
    """Parse one row, refusing anything the predicate should have excluded.

    The SQL predicate is the control; this is the assertion the control held — the same
    fail-loud discipline `learning._row_to_quarantined` (status) and `lifecycle._require_scoped`
    (project) apply. A wrong-project or non-quarantined row here would otherwise flow into the
    worker's independence resolution (a disclosure) or an out-of-band promotion (a governance
    write), the two catastrophic invariant-4 shapes for this port.
    """
    if ProjectId(row["project_id"]) != project_id:  # pragma: no cover - RLS + predicate hold
        raise TracebedError(
            f"select_quarantined for project {project_id} returned memory {row['id']} "
            f"belonging to project {row['project_id']} -- invariant 4"
        )
    status = Status(row["status"])
    if status is not Status.QUARANTINED:  # pragma: no cover - predicate holds
        raise TracebedError(
            f"select_quarantined returned memory {row['id']} with status {status.value!r}: "
            "the status conjunct has been lost from the statement"
        )
    provenance_json: Any = row["provenance"]
    return QuarantinedMemoryRow(
        id=MemoryId(row["id"]),
        project_id=ProjectId(row["project_id"]),
        status=status,
        trust_tier=TrustTier(row["trust_tier"]),
        mem_type=MemType(row["mem_type"]),
        provenance=Provenance.from_json(provenance_json),
        status_changed_at=row["status_changed_at"],
        is_failure_lesson=bool(row["is_failure_lesson"]),
        confirming_run_ids=tuple(RunId(value) for value in (row["shadow_confirm_runs"] or ())),
    )
