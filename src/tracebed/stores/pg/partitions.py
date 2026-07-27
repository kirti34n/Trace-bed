"""Per-project partition manager (PHASE-0 Task 6; contract §5.5).

LIST partitioning is Tracebed's project-deletion mechanism (PLAN.md §5,
DECISIONS D-017): one partition per project per learning-plane table means
project deletion is DETACH+DROP across the 13 tables in
`tracebed.stores.pg.ddl.PARTITIONED_TABLES` in one transaction, instead of a
DELETE that has to visit every row. **Documented ceiling: 1,000 projects per
instance** (~13,000 partitions total) — the Postgres query planner considers
every partition of every partitioned table referenced in a plan even when
partition pruning eliminates most of them at execution time, and planning
time degrades measurably once a table's partition count reaches the low
thousands. **Migration path past the ceiling** (PLAN.md §5): new deployments
approaching 1,000 projects switch `PARTITION BY LIST (project_id)` to
`PARTITION BY HASH (project_id)` in the DDL; project deletion becomes a bulk
`DELETE FROM t WHERE project_id = $1` per table instead of DETACH+DROP. The
public API here — `create_project_partitions` / `drop_project` /
`ensure_schema_current` — does not change across that switch; per
DECISIONS D-017, "the repository hides the strategy." This module is where
that hiding happens: nothing outside `stores/pg/` should ever branch on
whether a deployment is LIST- or HASH-partitioned.

These functions take a raw `psycopg.Connection`, not a pooled connection from
`Repo` — they run DDL under migration/admin privileges (the app role granted
in migrations/0003_rls.sql has no CREATE/DROP/ALTER grants), never through
the RLS-scoped app connection `Repo` uses. `api/admin.py` reaches them
through `AppDeps.partitions` (contract §9.2), never via its own SQL.
"""

from __future__ import annotations

from typing import Any

import psycopg

from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.ddl import (
    PARTITIONED_TABLES,
    create_partition_sql,
    partition_grant_statements,
    partition_index_statements,
    partition_name,
    partition_rls_statements,
)

__all__ = [
    "PARTITIONED_TABLES",
    "create_project_partitions",
    "drop_project",
    "ensure_schema_current",
    "partition_name",
]

# Projects whose learning-plane data has been erased keep their registry row
# (PLAN.md §5: `project.deleted_at` is a soft-delete marker; removal happens
# through `drop_project`). `ensure_schema_current` must therefore filter them
# out, or it re-provisions writable storage for a deleted tenant.
_LIVE_PROJECTS_SQL = (
    "SELECT project_id FROM project WHERE deleted_at IS NULL AND status <> 'deleted'"
)

# to_regclass() resolves through search_path and returns NULL (not an error)
# for an absent relation — the only catalog lookup that is safe to run for a
# partition that may legitimately not exist yet.
_PARTITION_EXISTS_SQL = "SELECT to_regclass(%(name)s) IS NOT NULL"

_PARTITION_ATTACHED_SQL = (
    "SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = to_regclass(%(name)s))"
)


def _apply_partition_ddl(cur: psycopg.Cursor[Any], table: str, project_id: ProjectId) -> None:
    """One table's worth of partition + RLS + grants + indexes.

    Shared by `create_project_partitions` (new project) and
    `ensure_schema_current` (existing projects, new/changed DDL) so the two
    entry points can never diverge — the exact drift `ddl.py` exists to
    prevent (contract §5.5).
    """
    cur.execute(create_partition_sql(table, project_id))
    for stmt in partition_rls_statements(table, project_id):
        cur.execute(stmt)
    for stmt in partition_grant_statements(table, project_id):
        cur.execute(stmt)
    for stmt in partition_index_statements(table, project_id):
        cur.execute(stmt)


def create_project_partitions(conn: psycopg.Connection[Any], project_id: ProjectId) -> None:
    """Create every per-project partition, its RLS setup, grants, and indexes.

    Called once at `POST /admin/projects` time (contract §9.3) and again,
    harmlessly, by `ensure_schema_current` for tables added by a later
    migration. Fully idempotent (`IF NOT EXISTS` / `DROP ... IF EXISTS` then
    recreate throughout `ddl.py`'s statements) — safe to call twice for the
    same project. All tables for one project are created in a single
    transaction: a failure partway through never leaves a project with only
    some of its partitions, which would leave invariant 4's RLS setup applied
    to some of a project's data and not the rest.
    """
    with conn.transaction(), conn.cursor() as cur:
        for table in PARTITIONED_TABLES:
            _apply_partition_ddl(cur, table, project_id)


def drop_project(conn: psycopg.Connection[Any], project_id: ProjectId) -> None:
    """Detach + drop `project_id`'s partition from every partitioned table.

    ONE transaction across all 13 tables (PHASE-0 Task 6's proving test:
    drop one of two projects, assert the other is untouched) — either every
    partition for this project disappears, or (on any error) none do.
    Plain `DETACH PARTITION` (not `DETACH ... CONCURRENTLY`, which cannot
    run inside a multi-statement transaction block) briefly locks the parent
    table; at Phase 0 scale this is a bounded, acceptable cost for admin-path
    project deletion.

    Tolerates a project that is missing some partitions (provisioned before a
    later migration added a table, or a half-finished earlier drop). This is
    the erasure path: a project that cannot be deleted because one partition
    is absent would be a compliance failure, not a safety feature.
    """
    with conn.transaction(), conn.cursor() as cur:
        for table in PARTITIONED_TABLES:
            name = partition_name(table, project_id)
            cur.execute(_PARTITION_EXISTS_SQL, {"name": name})
            row = cur.fetchone()
            if row is None or not row[0]:
                continue
            cur.execute(_PARTITION_ATTACHED_SQL, {"name": name})
            attached = cur.fetchone()
            if attached is not None and attached[0]:
                cur.execute(f"ALTER TABLE {table} DETACH PARTITION {name}")
            cur.execute(f"DROP TABLE IF EXISTS {name}")


def ensure_schema_current(conn: psycopg.Connection[Any]) -> None:
    """Apply pending per-partition DDL to every live project's partitions.

    The counterpart to `create_project_partitions`: a partition created
    before a later migration added a new index (or before this module
    started granting/re-securing per partition) does not silently keep the
    old shape forever. Discovers project ids from the `project` registry
    table directly rather than through `Repo.list_project_ids` — `Repo` and
    `partitions` both live under `stores/pg/` and both execute SQL directly;
    reading the registry here keeps this module's only dependency
    `stores/pg/ddl` plus the DB itself.

    Soft-deleted projects are skipped: their partitions were dropped by
    `drop_project` and their registry row deliberately survives, so an
    unfiltered scan would re-create writable, RLS-enabled storage for a
    tenant whose data was erased.

    One transaction scope PER PROJECT, not one for the whole run: on an
    autocommit connection (what admin/migration tooling uses) that is a real
    transaction per project, so the ACCESS EXCLUSIVE locks a project's DDL
    takes on all 13 parents are released between projects instead of being
    held across the documented 1,000-project ceiling (~65,000 DDL statements
    in one lock window is an outage, not a migration). On a non-autocommit
    connection psycopg nests these as savepoints inside the caller's
    transaction — the caller's choice, and still per-project atomic.
    """
    with conn.cursor() as cur:
        cur.execute(_LIVE_PROJECTS_SQL)
        project_ids = [ProjectId(row[0]) for row in cur.fetchall()]

    for project_id in project_ids:
        with conn.transaction(), conn.cursor() as cur:
            for table in PARTITIONED_TABLES:
                _apply_partition_ddl(cur, table, project_id)
