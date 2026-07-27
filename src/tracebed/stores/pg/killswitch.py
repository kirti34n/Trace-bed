"""`KillswitchWriter` — the missing write half of `killswitch_state` (PLAN.md §6 `killswitch.*`;
D-027; the contract gap `workers/killswitch.py`'s module docstring pins down).

`workers.killswitch.KillswitchGridEvaluator` needs a store satisfying `KillswitchStorePort`
(`workers/killswitch.py:294-309`, one method: `write_killswitch_state`). Both drivers of that
evaluator — the automatic trigger (`apply()`, `disabled=True`) and the operator re-enable
(`record_override()`, `disabled=<operator choice>`) — flow through that ONE method; `safety_lift`'s
`evaluate_safety_grid` reuses the same evaluator. `Repo` already owns the two *readers* of this
table (`list_killswitch_state`, `get_killswitch_overlay`); this is a standalone writer so the
integration wiring does not have to touch that shared, high-traffic file to add a single upsert.

WHY AN UPSERT WHEN THE FAKE IS A CALL SPY. `tests/phase3/test_killswitch.py`'s
`_FakeKillswitchStore` appends every call to a list — it is a spy on *which cells were written
with which args*, not a model of the table. The observable contract the worker actually relies on
is the one `workers/killswitch.py:76` states: an upsert on the scope cell, because the table keeps
no per-change history — `evidence`/`changed_at` describe the LATEST decision only. So this store
UPSERTS (latest decision wins per cell); it agrees with the fake on every property the tests check
(the write happened, with these exact args) while being the correct real-table semantics.

ISOLATION NUANCE — this is a 0001 REGISTRY table, DELIBERATELY NOT under RLS (migrations/0003
lists exactly the 13 partitioned tables; the 0001 registries are excluded). There is therefore no
RLS FORCE backstop and no partition pruning here: the explicit `project_id = %(project_id)s` value
in the VALUES tuple, carried into the COALESCE conflict arbiter, is the ONLY row-scoping control.
Because `project_id` is part of the unique index, a connection scoped to project B physically
cannot conflict-match (and thus cannot overwrite) project A's row — B's write conflicts only with
B's own prior row for the same `(mem_type, agent_type)` cell. `scoped()` is still used for uniform
transaction discipline with the two existing readers, but the GUC it sets is INERT for this table
and must not be relied on as the isolation mechanism — the predicate/arbiter carry the whole load.

CLOCK DISCIPLINE (hard rule 5). All six columns are written explicitly. `changed_at` comes from
the caller's `changed_at` PARAMETER (the worker owns it via `KillswitchGridEvaluator._moment`,
already tz-aware) — never `now()`: the column DEFAULT is the server wall clock AND fires only on
INSERT, so an upserted row would otherwise keep its stale first timestamp.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Final

from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

from tracebed.domain.enums import MemType
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.stores.pg.pool import scoped

# The ON CONFLICT target MUST be the EXPRESSION index `killswitch_state_scope_uq`
# (migrations/0001:149-154), not a plain column tuple: `killswitch_state` has NO primary key and
# its only unique index is over the COALESCE expression. A plain `ON CONFLICT (project_id,
# agent_type_id, mem_type)` would (a) find no matching arbiter index and raise, and (b) never
# conflict-match a NULL (project-wide) agent_type_id row — reintroducing the "NULL scope never
# matches" bug family (D-129). The sentinel UUID matches migrations/0001 character-for-character.
_WRITE_KILLSWITCH_SQL: Final[str] = """
INSERT INTO killswitch_state
    (project_id, agent_type_id, mem_type, disabled, evidence, changed_at)
VALUES
    (%(project_id)s, %(agent_type_id)s, %(mem_type)s, %(disabled)s, %(evidence)s, %(changed_at)s)
ON CONFLICT (project_id, mem_type, COALESCE(agent_type_id, '00000000-0000-0000-0000-000000000000'::uuid))
DO UPDATE SET
    disabled = EXCLUDED.disabled,
    evidence = EXCLUDED.evidence,
    changed_at = EXCLUDED.changed_at
"""


class KillswitchWriter:
    """The write side of `killswitch_state`, satisfying `workers.killswitch.KillswitchStorePort`.

    Takes the bare pool (like `Repo`/`WorkQueue`), not a `scoped()` connection — every write opens
    its own scoped, single-statement transaction and is atomic on its own.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def write_killswitch_state(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId | None,
        mem_type: MemType,
        *,
        disabled: bool,
        evidence: Mapping[str, object],
        changed_at: datetime,
    ) -> None:
        """Upsert the one `killswitch_state` cell for `(project_id, agent_type_id, mem_type)`.

        `agent_type_id` is widened to `AgentTypeId | None` (still structurally satisfying the
        Protocol's non-optional `AgentTypeId` by parameter contravariance) so a project-wide
        overlay row (`agent_type_id IS NULL`) can also be written; every current worker call site
        passes a concrete non-NULL id. `mem_type` is bound as its `.value` to satisfy the column
        CHECK; `evidence` is stored verbatim via `Json(dict(evidence))` so `list_killswitch_state`
        reads back the worker's keys unreshaped; `changed_at` is the caller's tz-aware instant.
        """
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                _WRITE_KILLSWITCH_SQL,
                {
                    "project_id": project_id,
                    "agent_type_id": agent_type_id,
                    "mem_type": mem_type.value,
                    "disabled": disabled,
                    "evidence": Json(dict(evidence)),
                    "changed_at": changed_at,
                },
            )
