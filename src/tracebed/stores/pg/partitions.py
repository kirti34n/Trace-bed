"""Per-project partition manager (PHASE-0 Task 6; contract §5.5).

LIST partitioning is Tracebed's storage layout (PLAN.md §5, DECISIONS D-017).
The historical Python detach/drop helper is deliberately private now: E3's
credential-separated SECURITY DEFINER routine is the only supported project
erasure path.  Keeping destructive DDL out of normal lifecycle code prevents
an ordinary runtime/vector adapter from turning a local cleanup request into a
whole-project deletion. **Documented ceiling: 1,000 projects per
instance** (~17,000 partitions total) — the Postgres query planner considers
every partition of every partitioned table referenced in a plan even when
partition pruning eliminates most of them at execution time, and planning
time degrades measurably once a table's partition count reaches the low
thousands. **Migration path past the ceiling** (PLAN.md §5): new deployments
approaching 1,000 projects switch `PARTITION BY LIST (project_id)` to
`PARTITION BY HASH (project_id)` in the DDL.  E3 owns the corresponding
destructive catalog operation; normal code only provisions/repairs children.

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
    partition_index_expectations,
    partition_index_statements,
    partition_name,
    partition_rls_statements,
)

__all__ = [
    "PARTITIONED_TABLES",
    "create_project_partitions",
    "ensure_schema_current",
    "partition_name",
]

# Projects whose learning-plane data has been erased keep their registry row
# (PLAN.md §5: `project.deleted_at` is a soft-delete marker; removal happens
# through `drop_project`). `ensure_schema_current` must therefore filter them
# out, or it re-provisions writable storage for a deleted tenant.
_LIVE_PROJECTS_SQL = (
    "SELECT project_id FROM public.project "
    "WHERE status IN ('active', 'suspended') AND deleted_at IS NULL"
)

# to_regclass() resolves through search_path and returns NULL (not an error)
# for an absent relation — the only catalog lookup that is safe to run for a
# partition that may legitimately not exist yet.
_PARTITION_EXISTS_SQL = "SELECT to_regclass(%(qualified)s::text) IS NOT NULL"

_PARTITION_EXACT_ATTACHMENT_SQL = """
SELECT EXISTS (
    SELECT 1
      FROM pg_class AS child
      JOIN pg_inherits AS inheritance ON inheritance.inhrelid = child.oid
     WHERE child.oid = to_regclass(%(qualified)s::text)
       AND child.relkind = 'r'
       AND inheritance.inhparent = %(parent)s::regclass
       AND pg_get_expr(child.relpartbound, child.oid)
           = format('FOR VALUES IN (%%L)', %(project_id)s::uuid)
)
"""

_PARTITION_FOR_PROJECT_SQL = """
SELECT child_schema.nspname, child.relname
  FROM pg_class AS child
  JOIN pg_namespace AS child_schema ON child_schema.oid = child.relnamespace
  JOIN pg_inherits AS inheritance ON inheritance.inhrelid = child.oid
 WHERE child.relkind = 'r'
   AND inheritance.inhparent = %(parent)s::regclass
   AND pg_get_expr(child.relpartbound, child.oid)
       = format('FOR VALUES IN (%%L)', %(project_id)s::uuid)
 ORDER BY child.relname
"""

_PARTITION_INDEX_SHAPE_SQL = """
SELECT index_data.indrelid = %(partition)s::regclass,
       access_method.amname,
       index_data.indisvalid AND index_data.indisready AND index_data.indislive,
       NOT index_data.indisunique AND NOT index_data.indisprimary AND NOT index_data.indisexclusion,
       index_data.indnkeyatts = index_data.indnatts,
       ARRAY(
           SELECT key_position.attribute_number::integer
             FROM unnest(index_data.indkey::smallint[]) WITH ORDINALITY
                  AS key_position(attribute_number, ordinality)
            ORDER BY key_position.ordinality
       ),
       ARRAY(
           SELECT key_option.option_value::integer
             FROM unnest(index_data.indoption::smallint[]) WITH ORDINALITY
                  AS key_option(option_value, ordinality)
            ORDER BY key_option.ordinality
       ),
       ARRAY(
           SELECT opclass_schema.nspname || '.' || opclass.opcname
             FROM unnest(index_data.indclass::oid[]) WITH ORDINALITY
                  AS key_opclass(opclass_oid, ordinality)
             JOIN pg_opclass AS opclass ON opclass.oid = key_opclass.opclass_oid
             JOIN pg_namespace AS opclass_schema ON opclass_schema.oid = opclass.opcnamespace
            ORDER BY key_opclass.ordinality
       ),
       ARRAY(
           SELECT opclass.opcdefault
             FROM unnest(index_data.indclass::oid[]) WITH ORDINALITY
                  AS key_opclass(opclass_oid, ordinality)
             JOIN pg_opclass AS opclass ON opclass.oid = key_opclass.opclass_oid
            ORDER BY key_opclass.ordinality
       ),
       (
           SELECT array_agg(attribute.attname ORDER BY key_position.ordinality)
             FROM unnest(index_data.indkey::smallint[]) WITH ORDINALITY
                  AS key_position(attribute_number, ordinality)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = index_data.indrelid
              AND attribute.attnum = key_position.attribute_number
       ),
       (
           SELECT bool_and(key_position.attribute_number > 0 AND key_collation.collation_oid = attribute.attcollation)
             FROM unnest(index_data.indkey::smallint[]) WITH ORDINALITY
                  AS key_position(attribute_number, ordinality)
             JOIN unnest(index_data.indcollation::oid[]) WITH ORDINALITY
                  AS key_collation(collation_oid, ordinality)
               USING (ordinality)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = index_data.indrelid
              AND attribute.attnum = key_position.attribute_number
       ),
       pg_get_expr(index_data.indpred, index_data.indrelid)
  FROM pg_class AS index_class
  JOIN pg_namespace AS index_schema ON index_schema.oid = index_class.relnamespace
  JOIN pg_index AS index_data ON index_data.indexrelid = index_class.oid
  JOIN pg_am AS access_method ON access_method.oid = index_class.relam
 WHERE index_class.oid = to_regclass(%(index)s::text)
   AND index_schema.nspname = 'public'
"""


def _require_exact_partition(
    cur: psycopg.Cursor[Any], table: str, project_id: ProjectId, name: str
) -> None:
    """Reject a same-name ordinary/wrong-bound relation before mutating it."""

    cur.execute(
        _PARTITION_EXACT_ATTACHMENT_SQL,
        {
            "qualified": f"public.{name}",
            "parent": f"public.{table}",
            "project_id": str(project_id.value),
        },
    )
    row = cur.fetchone()
    if row is None or len(row) != 1 or row[0] is not True:
        raise RuntimeError("project partition name is occupied by an unexpected relation")


def _quoted_relation(schema_name: str, relation_name: str) -> str:
    """Return a catalog-derived relation name as two safe SQL identifiers."""

    return '"' + schema_name.replace('"', '""') + '"."' + relation_name.replace('"', '""') + '"'


def _apply_partition_ddl(
    cur: psycopg.Cursor[Any],
    table: str,
    project_id: ProjectId,
    *,
    authority_cutover: bool,
    erasure_foundation: bool,
) -> None:
    """One table's worth of partition + RLS + grants + indexes.

    Shared by `create_project_partitions` (new project) and
    `ensure_schema_current` (existing projects, new/changed DDL) so the two
    entry points can never diverge — the exact drift `ddl.py` exists to
    prevent (contract §5.5).
    """
    name = partition_name(table, project_id)
    cur.execute(create_partition_sql(table, project_id))
    _require_exact_partition(cur, table, project_id, name)
    # ``CREATE INDEX IF NOT EXISTS`` otherwise accepts a pre-planted canonical
    # name.  Check every existing index before any partition repair mutation,
    # then recheck after a new CREATE below.
    _reject_unexpected_partition_indexes(
        cur, table, project_id, name, erasure_foundation=erasure_foundation
    )
    for stmt in partition_rls_statements(
        table, project_id, erasure_foundation=erasure_foundation
    ):
        cur.execute(stmt)
    for stmt in partition_grant_statements(
        table,
        project_id,
        authority_cutover=authority_cutover,
        erasure_foundation=erasure_foundation,
    ):
        cur.execute(stmt)
    for stmt, expectation in zip(
        partition_index_statements(table, project_id, erasure_foundation=erasure_foundation),
        partition_index_expectations(table, project_id, erasure_foundation=erasure_foundation),
        strict=True,
    ):
        if _partition_index_shape(cur, expectation[0], name) is None:
            cur.execute(stmt)
        _require_exact_partition_index(cur, expectation, name)


def _partition_index_shape(
    cur: psycopg.Cursor[Any], index_name: str, partition: str
) -> tuple[Any, ...] | None:
    cur.execute(
        _PARTITION_INDEX_SHAPE_SQL,
        {"index": f"public.{index_name}", "partition": f"public.{partition}"},
    )
    return cur.fetchone()


def _require_exact_partition_index(
    cur: psycopg.Cursor[Any], expectation: tuple[str, str, str, str | None], partition: str
) -> None:
    """Require a canonical index's parent, AM/opclass keys, and predicate."""

    index_name, access_method, keys, predicate = expectation
    row = _partition_index_shape(cur, index_name, partition)
    expected_attributes: list[str] = []
    expected_opclasses: list[str | None] = []
    expected_options: list[int] = []
    for part in keys.split(", "):
        terms = part.split()
        if not terms:
            raise RuntimeError("partition index expectation has invalid keys")
        attribute = terms.pop(0)
        descending = terms[-1:] == ["DESC"]
        if descending:
            terms.pop()
        if len(terms) > 1:
            raise RuntimeError("partition index expectation has invalid keys")
        expected_attributes.append(attribute)
        # The DDL has a pinned ``pg_catalog, public`` search path.  An
        # unqualified opclass in its canonical specification therefore means
        # the public extension opclass, never whichever object a caller made
        # visible in an attacker-controlled path.
        expected_opclasses.append(
            None if not terms else (terms[0] if "." in terms[0] else f"public.{terms[0]}")
        )
        # PostgreSQL represents the default DESC ordering as DESC|NULLS FIRST
        # (3); ASC's default NULLS LAST is 0.  Compare the bit pattern rather
        # than deparsed SQL so PG18's deliberately abbreviated key text does
        # not conceal an ordering drift.
        expected_options.append(3 if descending else 0)
    expected_predicate = predicate
    if predicate is not None:
        expected_predicate = {
            "state IN ('pending', 'retry')": "(state = ANY (ARRAY['pending'::text, 'retry'::text]))",
            "state = 'running'": "(state = 'running'::text)",
        }.get(predicate, predicate)
    if (
        row is None
        or len(row) != 12
        or row[0] is not True
        or row[1] != access_method
        or row[2] is not True
        or row[3] is not True
        or row[4] is not True
        # ``indkey`` must name exactly one stored attribute per expected key;
        # the corresponding catalog attribute names below bind those attnums
        # to the canonical DDL columns without assuming physical attnum values
        # that can differ after an historical schema upgrade.
        or len(row[5]) != len(expected_attributes)
        or any(
            not isinstance(attnum, int) or isinstance(attnum, bool) or attnum <= 0
            for attnum in row[5]
        )
        or tuple(row[6]) != tuple(expected_options)
        or tuple(row[9]) != tuple(expected_attributes)
        or row[10] is not True
        or row[11] != expected_predicate
        or len(row[7]) != len(expected_opclasses)
        or len(row[8]) != len(expected_opclasses)
        or any(
            (actual_opclass != expected_opclass)
            if expected_opclass is not None
            else actual_default is not True
            for actual_opclass, actual_default, expected_opclass in zip(
                row[7], row[8], expected_opclasses, strict=True
            )
        )
    ):
        raise RuntimeError("project partition index name is occupied by an unexpected relation")


def _reject_unexpected_partition_indexes(
    cur: psycopg.Cursor[Any],
    table: str,
    project_id: ProjectId,
    partition: str,
    *,
    erasure_foundation: bool,
) -> None:
    """Fail before repair if a canonical index name already has another shape."""

    for expectation in partition_index_expectations(
        table, project_id, erasure_foundation=erasure_foundation
    ):
        row = _partition_index_shape(cur, expectation[0], partition)
        if row is not None:
            _require_exact_partition_index(cur, expectation, partition)


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
        cur.execute("SET LOCAL search_path = pg_catalog, public")
        cur.execute("SELECT to_regclass('public.authority_cutover_state') IS NOT NULL")
        cutover_row = cur.fetchone()
        if cutover_row is None or len(cutover_row) != 1 or not isinstance(cutover_row[0], bool):
            raise RuntimeError("database returned an invalid authority-cutover schema probe")
        cur.execute("SELECT to_regclass('public.erasure_cutover_state') IS NOT NULL")
        erasure_row = cur.fetchone()
        if erasure_row is None or len(erasure_row) != 1 or not isinstance(erasure_row[0], bool):
            raise RuntimeError("database returned an invalid erasure-foundation schema probe")
        for table in PARTITIONED_TABLES:
            # E2 adds five parents atomically.  A c11 database can still use
            # this library while its unreleased migration is staged, but an
            # E1-marked catalog missing any one of its parents is drift rather
            # than a legacy shape and must fail closed.
            cur.execute("SELECT to_regclass(%(parent)s)", {"parent": f"public.{table}"})
            parent_row = cur.fetchone()
            if parent_row is None or len(parent_row) != 1:
                raise RuntimeError("database returned an invalid partition parent probe")
            if parent_row[0] is None:
                if erasure_row[0]:
                    raise RuntimeError("erasure-foundation partition parent is missing")
                continue
            _apply_partition_ddl(
                cur,
                table,
                project_id,
                authority_cutover=cutover_row[0],
                erasure_foundation=erasure_row[0],
            )


def _drop_project_for_pre_e3_test_only(conn: psycopg.Connection[Any], project_id: ProjectId) -> None:
    """Historical detach/drop implementation retained only for migration tests.

    ONE transaction across every project-keyed parent (PHASE-0 Task 6's proving test:
    drop one of two projects, assert the other is untouched) — either every
    partition for this project disappears, or (on any error) none do.
    Plain `DETACH PARTITION` (not `DETACH ... CONCURRENTLY`, which cannot
    run inside a multi-statement transaction block) briefly locks the parent
    table; at Phase 0 scale this is a bounded, acceptable cost for admin-path
    project deletion.

    Do not call this from runtime or adapters.  E3 intentionally has stricter
    catalog checks (all 22 parents must be present before the first drop) and
    runs under the separately scoped executor capability.
    """
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("SET LOCAL search_path = pg_catalog, public")
        for table in PARTITIONED_TABLES:
            cur.execute(
                _PARTITION_FOR_PROJECT_SQL,
                {"parent": f"public.{table}", "project_id": str(project_id.value)},
            )
            attached = cur.fetchall()
            if len(attached) > 1 or any(
                len(row) != 2 or not isinstance(row[0], str) or not isinstance(row[1], str)
                for row in attached
            ):
                raise RuntimeError("project partition catalog has an ambiguous relation")
            if attached:
                schema_name, relation_name = attached[0]
                # Resolve from the public parent plus exact LIST bound rather
                # than a canonical spelling: attached partitions can be
                # renamed or moved, and erasure must still remove the genuine
                # child without touching an unrelated homonym.
                qualified_child = _quoted_relation(schema_name, relation_name)
                cur.execute(f"ALTER TABLE public.{table} DETACH PARTITION {qualified_child}")
                cur.execute(f"DROP TABLE {qualified_child}")
                continue
            # A canonical same-name ordinary/wrong-bound public relation must
            # never be silently ignored by erasure.  Non-public homonyms are
            # not lifecycle-owned unless attached to the exact public parent
            # with this project's bound (the catalog query above catches that).
            name = partition_name(table, project_id)
            cur.execute(_PARTITION_EXISTS_SQL, {"qualified": f"public.{name}"})
            row = cur.fetchone()
            if row is not None and row[0]:
                _require_exact_partition(cur, table, project_id, name)


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
    takes on every project-keyed parent are released between projects instead of being
    held across the documented 1,000-project ceiling (~85,000 DDL statements
    in one lock window is an outage, not a migration). On a non-autocommit
    connection psycopg nests these as savepoints inside the caller's
    transaction — the caller's choice, and still per-project atomic.
    """
    with conn.cursor() as cur:
        cur.execute(_LIVE_PROJECTS_SQL)
        project_ids = [ProjectId(row[0]) for row in cur.fetchall()]

    for project_id in project_ids:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("SET LOCAL search_path = pg_catalog, public")
            cur.execute("SELECT to_regclass('public.authority_cutover_state') IS NOT NULL")
            cutover_row = cur.fetchone()
            if cutover_row is None or len(cutover_row) != 1 or not isinstance(cutover_row[0], bool):
                raise RuntimeError("database returned an invalid authority-cutover schema probe")
            cur.execute("SELECT to_regclass('public.erasure_cutover_state') IS NOT NULL")
            erasure_row = cur.fetchone()
            if erasure_row is None or len(erasure_row) != 1 or not isinstance(erasure_row[0], bool):
                raise RuntimeError("database returned an invalid erasure-foundation schema probe")
            for table in PARTITIONED_TABLES:
                # The library is shared by c11 administration and the staged
                # c12 foundation.  A missing E1 parent is expected only
                # before its singleton exists; once that marker is present it
                # is authenticated catalog drift, never a reason to skip a
                # project's storage repair.
                cur.execute("SELECT to_regclass(%(parent)s)", {"parent": f"public.{table}"})
                parent_row = cur.fetchone()
                if parent_row is None or len(parent_row) != 1:
                    raise RuntimeError("database returned an invalid partition parent probe")
                if parent_row[0] is None:
                    if erasure_row[0]:
                        raise RuntimeError("erasure-foundation partition parent is missing")
                    continue
                _apply_partition_ddl(
                    cur,
                    table,
                    project_id,
                    authority_cutover=cutover_row[0],
                    erasure_foundation=erasure_row[0],
                )
