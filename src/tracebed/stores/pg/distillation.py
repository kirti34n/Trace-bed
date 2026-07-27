"""Postgres implementation of `workers.distiller.KnownDistillationPort` (FIDELITY-AUDIT.md
M3; PLAN.md §11.1).

THE CONTRACT GAP THIS CLOSES. `workers/distiller.py` declares `KnownDistillationPort` as a
local `Protocol` and its own docstring reports the gap in code: "no method on
`stores.pg.repo.Repo` satisfies this today -- no signature-scoped query over `memory_item`
exists at all". Its sibling port `TraceIndexPort` is byte-for-byte
`stores.pg.repo.Repo.get_trace_index` (which already exists), so ONLY `KnownDistillationPort`
needs a new store -- this module is that one read method, nothing more.

WHAT IT READS. Quality-lane distillations are `memory_item` rows the distiller wrote with
`provenance.class = 'distiller'` (`workers/distiller.py`'s write path, D-020). Their contributing
runs' input-signature hashes live inside the `provenance` jsonb as `input_sig_hashes[]` (one
40-byte hex hash per contributing run) -- `memory_item` has no signature column, exactly as it
has no `run_id` column and `Repo._COUNT_PROPOSALS_IN_RUN_SQL` reads a proposal's run from
`provenance->>'run_id'`. The discriminator is therefore `provenance->>'class' = 'distiller'`,
the identical jsonb-text idiom `repo.py`'s `_PROPOSAL_PREDICATE` uses, and the signatures are
rehydrated through `domain.memory.Provenance.from_json` (the one established parse path,
`learning.py`/`repo.py`).

INVARIANT 4 ON EVERY STATEMENT. The one read takes `ProjectId` first, opens its own `scoped()`
transaction (which issues the `tracebed.project_id` GUC as the transaction's first statement),
and carries `project_id = %(project_id)s` in the statement's own predicate. The predicate is
the primary control and the LIST-partition pruning key on `memory_item`; RLS FORCE
(migrations/0003) is the backstop. Together a store scoped to project B can physically neither
SELECT nor build an `ExistingDistillation` that references project A's row -- which is why the
worker's own `existing.project_id != scope.project_id` sweep (`distiller._find_duplicate`) can
treat any foreign row as a broken control and raise, and why this store must never hand it one.
A leak here would let one project's memory-content clustering suppress (or falsely accuse) another
project's distillation -- invariant 4 / PLAN.md §10's "never cross-project aggregation".

NO STATUS, NO WRITE. This is a pure read on the distiller's pre-LLM novelty gate; it assigns
nothing and moves no memory between statuses.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.enums import ProvenanceClass
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.memory import Provenance
from tracebed.stores.pg.pool import scoped
from tracebed.workers.distiller import ExistingDistillation

__all__ = ["KnownDistillationRepo"]


# `provenance->>'class'` is the discriminator (`domain.memory.Provenance.to_json`), kept as a
# literal jsonb extraction bound to `%(provenance_class)s` -- the exact idiom
# `repo.py`'s `_PROPOSAL_PREDICATE` uses for the same reason (`memory_item` has no signature
# column; a distillation's contributing hashes live only in `provenance`). `ORDER BY created_at,
# id` is the deterministic order the port's fake-fidelity contract requires: the worker returns
# the FIRST cluster match as `duplicate_of`, so the first-seeded same-cluster distillation must
# win -- the same ordering `CorroborationRepo.select_quarantined` uses.
_SELECT_DISTILLATIONS_SQL: Final[str] = """
SELECT id, project_id, provenance
FROM memory_item
WHERE project_id = %(project_id)s
  AND provenance->>'class' = %(provenance_class)s
ORDER BY created_at, id
""".strip()


class KnownDistillationRepo:
    """`workers.distiller.KnownDistillationPort` over Postgres.

    Satisfies the Protocol structurally (never by inheritance -- the Protocol lives in
    `workers/`, and importing it here for a base class would invert the dependency direction
    every store in this package keeps; `stores/pg` importing the worker's `ExistingDistillation`
    dataclass is the established pattern, mirroring `learning.py` importing
    `QuarantinedMemoryForCorroboration`). `tests/phase3/test_pg_distillation.py` asserts the
    `isinstance` against the `runtime_checkable` Protocol so a signature drift on either side
    fails a test rather than a deployment.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def existing_signatures(self, project_id: ProjectId) -> Sequence[ExistingDistillation]:
        """Every input-signature hash carried by THIS project's quality-lane distillations, one
        `ExistingDistillation` per `(memory_id, hash)` pair, in `(created_at, id)` order with each
        memory's provenance-array order preserved.

        Fake-fidelity note: `_FakeKnownDistillations.existing_signatures` returns EVERY seeded
        entry regardless of the `project_id` argument -- deliberately, to exercise the worker's
        `_find_duplicate` foreign-project backstop. The real store must NOT reproduce that
        shortcut: the `project_id` predicate + RLS guarantee every returned row is this project's,
        so `_row_to_distillations`'s re-assertion never fires and the worker's sweep is only ever
        given same-project rows. The observable contract the store DOES replicate is the fake's
        method contract: return the set of `(memory_id, input_signature_hash)` pairs for this
        project, each as one `ExistingDistillation` with `project_id == the argument`.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _SELECT_DISTILLATIONS_SQL,
                {
                    "project_id": project_id,
                    "provenance_class": ProvenanceClass.DISTILLER.value,
                },
            )
            rows = cur.fetchall()
        result: list[ExistingDistillation] = []
        for row in rows:
            result.extend(_row_to_distillations(row, project_id))
        return result


def _row_to_distillations(
    row: DictRow, project_id: ProjectId
) -> list[ExistingDistillation]:
    """Parse one `memory_item` row into one `ExistingDistillation` per contributing hash.

    Two fail-loud re-assertions the predicate should have made unnecessary, kept as the
    assertion that the control held (the same discipline `learning.py._row_to_quarantined` and
    `stores.pg.search._row_to_arm_hit` apply): the row's `project_id` must be the scoped one
    (a leak would be caught here rather than handed to the worker), and its provenance class must
    be `distiller` (the SQL discriminator's own conjunct). Each `input_sig_hash` is already the
    40 raw bytes `Provenance.from_json` decoded, so `ExistingDistillation.__post_init__`'s length
    check passes; a malformed one raises there, loudly, rather than reaching the novelty gate.
    """
    row_project = ProjectId(row["project_id"])
    if row_project != project_id:  # pragma: no cover - predicate + RLS hold; see docstring
        raise TracebedError(
            f"existing_signatures returned memory {row['id']} in project {row_project}, not the "
            f"scoped {project_id}: the project predicate has been lost from the statement"
        )
    provenance_json: Any = row["provenance"]
    provenance = Provenance.from_json(provenance_json)
    if provenance.cls is not ProvenanceClass.DISTILLER:  # pragma: no cover - predicate holds
        raise TracebedError(
            f"existing_signatures returned memory {row['id']} with provenance class "
            f"{provenance.cls.value!r}: the provenance discriminator has been lost from the "
            "statement"
        )
    memory_id = MemoryId(row["id"])
    return [
        ExistingDistillation(
            project_id=project_id,
            memory_id=memory_id,
            input_signature_hash=h,
        )
        for h in provenance.input_sig_hashes
    ]
