"""Postgres implementation of `workers.derived_state.DerivedStateStorePort`
(FIDELITY-AUDIT.md M3/M4 — "DerivedStateStorePort has no Postgres implementation
and the derived_state table has no writer", `workers/composition.py:169-170`).

`workers/derived_state.py` declares the store primitive `DerivedStateWriter`
needs as a local `@runtime_checkable Protocol` and reports the concrete
implementation as a contract_gap, exactly as `workers/embedder.py` and
`workers/corroboration.py` did for `stores.pg.learning`. This module is that
implementation, and it is the structural analogue of `stores.pg.learning`:

* one class satisfying its worker's Protocol STRUCTURALLY (never by inheritance
  — the Protocol lives in `workers/`, and `stores/pg/` importing a worker module
  for a base class would invert the dependency direction every other store in
  this package keeps; importing it for the row dataclass is fine, and is what
  `stores.pg.learning` does with `EmbeddingCandidateRow`);
* every method opens its own `scoped()` transaction (which issues the
  `tracebed.project_id` GUC as the transaction's first statement) and carries
  `project_id = %(project_id)s` in the statement's own predicate. The GUC and
  the predicate are not redundant: RLS FORCE (migrations/0003_rls.sql) is the
  backstop for a statement that forgot the predicate, and the predicate is the
  control for a connection whose GUC was never set — and it is what prunes the
  LIST partition (migrations/0002_partitioned.sql).

THE ONE PROTOCOL-FORCED ASYMMETRY. `recent_versions`/`prune_versions` take
`ProjectId` positionally; `append_version` does NOT — the Protocol passes the
scope INSIDE the row (`version.project_id`). This module replicates the signature
exactly and scopes `append_version` on `version.project_id`, never a positional
argument, because there is none.

VALUE IS A JSONB BRIDGE POINT. `derived_state.value` is `jsonb` in the DDL but
`DerivedStateVersion.value` is a plain `float` (the dataclass docstring documents
this deliberately, flagging a structured-jsonb caller as out of scope). The write
wraps the float in `psycopg.types.json.Jsonb` (the `stores.pg.queue` idiom); the
read decodes a jsonb number straight back to a Python `float`. `computed_at` is
written EXPLICITLY from the writer's Clock value, never left to the column
`DEFAULT now()`: every divergence window the writer computes is "how long ago"
and is keyed off this exact instant, so a clock-substituted value would silently
mis-date the persisted history a restarted writer seeds from.

OBSERVABLE BEHAVIOUR MATCHES THE FAKE. The contract is
`tests/phase2/test_derived_state.py::FakeDerivedStateStore` (duplicated verbatim
in `harness/baseline_walk.py`): `recent_versions` returns the complete retained
set ascending by version (empty when the key was never written), `append_version`
is a plain INSERT with no ON CONFLICT (a re-appended version SHOULD raise — the
PK forbids overwriting an immutable row), and `prune_versions` deletes every
version except the most recent `keep`, which — because the writer assigns strictly
contiguous version numbers — is exactly `DELETE ... WHERE version <= (max - keep)`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from psycopg.rows import DictRow, dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.stores.pg.pool import scoped
from tracebed.workers.derived_state import DerivedStateVersion

__all__ = ["DerivedStateStore"]


# The complete retained set for one `(project, agent_type, key)`, ascending by
# `version` — the port's contracted order (`workers/derived_state.py`). The PK
# `(project_id, agent_type_id, key, version)` btree covers this lookup, so no
# extra index is needed (ddl.py defines none for derived_state).
_RECENT_VERSIONS_SQL: Final[str] = """
SELECT project_id, agent_type_id, key, version, value, computed_at, delta_pct, clamped
FROM derived_state
WHERE project_id = %(project_id)s
  AND agent_type_id = %(agent_type_id)s
  AND key = %(key)s
ORDER BY version ASC
""".strip()

# A plain INSERT with NO ON CONFLICT, deliberately: the writer never re-appends
# a version number, and a duplicate `(project_id, agent_type_id, key, version)`
# SHOULD raise rather than silently overwrite an immutable row (the port
# docstring makes this a correctness requirement). `computed_at` is bound
# explicitly, never left to the column DEFAULT.
_APPEND_VERSION_SQL: Final[str] = """
INSERT INTO derived_state
    (project_id, agent_type_id, key, version, value, computed_at, delta_pct, clamped)
VALUES
    (%(project_id)s, %(agent_type_id)s, %(key)s, %(version)s, %(value)s,
     %(computed_at)s, %(delta_pct)s, %(clamped)s)
""".strip()

# Keep the most recent `keep` versions, drop the rest. Versions are strictly
# contiguous (the writer sets `version_no = previous.version + 1`), so
# "everything but the newest `keep`" is exactly `version <= (max - keep)`. The
# subquery carries the same three-column predicate as the outer DELETE so it,
# too, prunes to this project's partition rather than scanning across projects.
_PRUNE_VERSIONS_SQL: Final[str] = """
DELETE FROM derived_state
WHERE project_id = %(project_id)s
  AND agent_type_id = %(agent_type_id)s
  AND key = %(key)s
  AND version <= (
      SELECT max(version)
      FROM derived_state
      WHERE project_id = %(project_id)s
        AND agent_type_id = %(agent_type_id)s
        AND key = %(key)s
  ) - %(keep)s
""".strip()


class DerivedStateStore:
    """`workers.derived_state.DerivedStateStorePort` over Postgres.

    Satisfies the Protocol structurally; the test module asserts the
    `isinstance` against the `runtime_checkable` Protocol so a signature drift
    on either side fails a test rather than a deployment.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def recent_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str
    ) -> Sequence[DerivedStateVersion]:
        """Every retained version for this key, oldest first (empty when the key
        has never been written) — the writer's only read.

        Returns the COMPLETE retained set: the writer maxes over it for the row
        the rate bound clamps against and reconstructs both watchdogs from the
        whole sequence, so a partial result would be a silently missing control.
        """
        with scoped(self._pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _RECENT_VERSIONS_SQL,
                {"project_id": project_id, "agent_type_id": agent_type_id, "key": key},
            )
            rows = cur.fetchall()
        return [_row_to_derived_state_version(row, project_id) for row in rows]

    def append_version(self, version: DerivedStateVersion) -> None:
        """Append one immutable version row. Scope + predicate come from
        `version.project_id` (the Protocol passes no positional `project_id`
        here — replicated exactly).

        A plain INSERT with no ON CONFLICT: a duplicate version number raises,
        matching the immutable-versioned-table contract the PK enforces.
        """
        with scoped(self._pool, version.project_id) as conn:
            conn.execute(
                _APPEND_VERSION_SQL,
                {
                    "project_id": version.project_id,
                    "agent_type_id": version.agent_type_id,
                    "key": version.key,
                    "version": version.version,
                    # BRIDGE POINT: the dataclass value is a plain float, the
                    # column is jsonb — wrap on write, decode on read.
                    "value": Jsonb(version.value),
                    "computed_at": version.computed_at,
                    "delta_pct": version.delta_pct,
                    "clamped": version.clamped,
                },
            )

    def prune_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str, *, keep: int
    ) -> None:
        """Delete every version for this key except the most recent `keep`.

        `keep >= 1` is guaranteed by the writer's `ConfigError` guard, but this
        method does not assume it — the statement is a pure predicate delete that
        stays correct for any non-negative `keep`.
        """
        with scoped(self._pool, project_id) as conn:
            conn.execute(
                _PRUNE_VERSIONS_SQL,
                {
                    "project_id": project_id,
                    "agent_type_id": agent_type_id,
                    "key": key,
                    "keep": keep,
                },
            )


def _row_to_derived_state_version(row: DictRow, project_id: ProjectId) -> DerivedStateVersion:
    """Parse one row, refusing anything the predicate should have excluded.

    The same fail-loud discipline `stores.pg.learning._row_to_embedding_candidate`
    applies: the SQL predicate (plus RLS FORCE and partition pruning) is the
    control, and this is the assertion that the control held. A row whose
    `project_id` is not the scoped project can only appear if every one of those
    controls was bypassed at once — turn it into a loud raise, never a silent
    cross-project leak.
    """
    row_project = ProjectId(row["project_id"])
    if row_project != project_id:  # pragma: no cover - predicate + RLS + partition hold
        raise TracebedError(
            f"recent_versions returned a row for project {row_project} while scoped to "
            f"{project_id}: the project_id predicate has been lost from the statement"
        )
    return DerivedStateVersion(
        project_id=row_project,
        agent_type_id=AgentTypeId(row["agent_type_id"]),
        key=str(row["key"]),
        version=int(row["version"]),
        # psycopg decodes a jsonb number straight to a Python float/int.
        value=float(row["value"]),
        computed_at=row["computed_at"],
        delta_pct=float(row["delta_pct"]),
        clamped=bool(row["clamped"]),
    )
