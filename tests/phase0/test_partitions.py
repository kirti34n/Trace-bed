"""tests/phase0/test_partitions.py — PHASE-0 Task 6 (contract §5.5, §13.2).

Offline (runs on every machine, no database): `stores.pg.ddl` is exercised as
the pure string builder it is, and `stores.pg.partitions` is exercised
against a recording fake connection. That second half matters more than it
looks: every property Task 6 actually cares about — RLS enabled AND forced
AND policied on *every* one of the 13 partitions, grants issued, the whole
per-project unit in one transaction, `drop_project` reaching all 13 tables,
`ensure_schema_current` not resurrecting deleted projects — is otherwise
only observable from an integration test that never runs on this machine.
A fake connection cannot prove Postgres accepts the SQL; it can prove the
SQL we emit is the SQL invariant 4 requires, and it goes red when someone
drops a statement from the sequence.

Integration (needs the compose PG18 stack, via the `pg_pool` / `pg_dsn` /
`two_projects` fixtures from `tests/phase0/conftest.py`, contract §13.1):
two projects get partitions and a row in every partitioned table;
`drop_project` removes one project's partitions in a single transaction
while the other project's partitions AND rows survive; the non-owner,
non-BYPASSRLS `tracebed_app` role reading with no GUC set sees zero rows
from every partitioned table — checked against a database that demonstrably
HAS rows, because "zero rows" from an empty table proves nothing.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from types import TracebackType
from typing import Any
from uuid import UUID

import pytest

from tracebed.domain.ids import ProjectId
from tracebed.stores.pg import partitions as partitions_mod
from tracebed.stores.pg.ddl import (
    PARTITIONED_TABLES,
    create_partition_sql,
    partition_grant_statements,
    partition_index_statements,
    partition_name,
    partition_policy_name,
    partition_rls_statements,
)

pytestmark = pytest.mark.phase0

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

PID_A = ProjectId("12345678-1234-5678-1234-567812345678")
PID_B = ProjectId("87654321-4321-8765-4321-876543214321")

# PostgreSQL's NAMEDATALEN - 1. Longer identifiers are silently truncated,
# which breaks every catalog lookup done by the constructed name.
PG_IDENT_MAX = 63

# `tracebed_app`'s credential belongs to deployment, not to a migration
# (docker/initdb/01-roles.sql for compose/CI). Overridable so the probe can
# run against a real stack instead of skipping.
_APP_ROLE_PASSWORD = os.environ.get("TB_APP_ROLE_PASSWORD", "tracebed_app_dev")


# --------------------------------------------------------------------------- #
# Offline — ddl.py string builders
# --------------------------------------------------------------------------- #


def test_ddl_partitioned_tables_match_migration() -> None:
    sql = (MIGRATIONS_DIR / "0002_partitioned.sql").read_text(encoding="utf-8")
    declared = set(
        re.findall(
            r"CREATE TABLE\s+(\w+)\s*\([\s\S]*?PARTITION BY LIST\s*\(\s*project_id\s*\)",
            sql,
            re.IGNORECASE,
        )
    )
    assert declared == set(PARTITIONED_TABLES), (
        "ddl.py's PARTITIONED_TABLES drifted from migrations/0002_partitioned.sql: "
        f"only-in-sql={declared - set(PARTITIONED_TABLES)} "
        f"only-in-ddl={set(PARTITIONED_TABLES) - declared}"
    )


def test_thirteen_tables_exactly() -> None:
    assert len(PARTITIONED_TABLES) == 13
    assert len(set(PARTITIONED_TABLES)) == 13  # no duplicate would be silently tolerated


def test_partition_name_is_deterministic_and_stable() -> None:
    name = partition_name("memory_item", PID_A)
    assert name == f"memory_item_p_{PID_A.value.hex}"
    assert partition_name("memory_item", PID_A) == name
    assert partition_name("memory_item", PID_B) != name


@pytest.mark.parametrize(
    "builder",
    [
        partition_name,
        partition_policy_name,
        create_partition_sql,
        partition_rls_statements,
        partition_grant_statements,
        partition_index_statements,
    ],
)
def test_every_builder_rejects_an_unknown_table(builder: Any) -> None:
    """`PARTITIONED_TABLES` is the whitelist that makes interpolating a table
    name into DDL safe (partitions.drop_project builds `DROP TABLE {name}`
    from it). A builder that accepts arbitrary text is an injection point."""
    with pytest.raises(ValueError, match="not a LIST-partitioned table"):
        builder("not_a_real_table; DROP TABLE project", PID_A)


def test_create_partition_sql_carries_no_bind_parameter() -> None:
    """PostgreSQL's `FOR VALUES IN (...)` grammar accepts literal constants
    only (`partbound_datum`). A `%(project_id)s` placeholder reaches the
    server as `$1` under psycopg's server-side binding and fails with a
    syntax error, so `create_project_partitions` would not create a single
    partition. This test is the offline stand-in for that server error."""
    for table in PARTITIONED_TABLES:
        sql = create_partition_sql(table, PID_A)
        assert "%s" not in sql and "%(" not in sql, sql
        assert "$1" not in sql, sql


def test_create_partition_sql_embeds_the_project_uuid_literal() -> None:
    sql = create_partition_sql("memory_item", PID_A)
    assert f"PARTITION OF memory_item FOR VALUES IN ('{PID_A.value}')" in sql
    # A cast is also a syntax error in a partition bound: partbound_datum is
    # Sconst, not a general expression.
    assert "::uuid" not in sql
    assert create_partition_sql("memory_item", PID_B) != sql


def test_create_partition_sql_is_idempotent_shaped() -> None:
    assert create_partition_sql("memory_item", PID_A).startswith("CREATE TABLE IF NOT EXISTS ")


@pytest.mark.parametrize("table", PARTITIONED_TABLES)
def test_generated_identifiers_fit_postgres_limit(table: str) -> None:
    """Every name we later look up by (`to_regclass(partition_name(...))`,
    `DROP POLICY {policy}`) must survive the server verbatim."""
    names = [partition_name(table, PID_A), partition_policy_name(table, PID_A)]
    for stmt in partition_index_statements(table, PID_A):
        match = re.search(r"CREATE INDEX IF NOT EXISTS (\S+)", stmt)
        assert match, stmt
        names.append(match.group(1))
    for name in names:
        assert len(name.encode("utf-8")) <= PG_IDENT_MAX, f"{name} ({len(name)} bytes)"


@pytest.mark.parametrize("table", PARTITIONED_TABLES)
def test_rls_statements_enable_force_and_policy(table: str) -> None:
    stmts = partition_rls_statements(table, PID_A)
    name = partition_name(table, PID_A)
    policy = partition_policy_name(table, PID_A)
    assert f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY" in stmts
    assert f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY" in stmts
    assert f"DROP POLICY IF EXISTS {policy} ON {name}" in stmts
    create = [s for s in stmts if s.startswith("CREATE POLICY")]
    assert len(create) == 1
    # DROP must precede CREATE or the re-issue from ensure_schema_current fails.
    assert stmts.index(f"DROP POLICY IF EXISTS {policy} ON {name}") < stmts.index(create[0])


def test_partition_policy_predicate_is_byte_identical_to_the_migration() -> None:
    """The parent tables' predicate (0003_rls.sql) and the per-partition
    predicate (ddl.py) are two copies of one security control. Drift between
    them is a silent isolation hole on exactly one of the two paths."""
    sql = (MIGRATIONS_DIR / "0003_rls.sql").read_text(encoding="utf-8")
    parent_predicates = {
        " ".join(m.split())
        for m in re.findall(r"CREATE POLICY \w+ ON \w+\s+USING \(([\s\S]*?)\);", sql)
    }
    assert len(parent_predicates) == 1, f"0003_rls.sql uses >1 predicate: {parent_predicates}"
    parent = parent_predicates.pop()

    for table in PARTITIONED_TABLES:
        create = next(
            s for s in partition_rls_statements(table, PID_A) if s.startswith("CREATE POLICY")
        )
        child = " ".join(create.split("USING (", 1)[1].rstrip(")").split())
        assert child == parent, f"{table}: partition predicate {child!r} != parent {parent!r}"


def test_policy_predicate_is_fail_closed_on_unset_and_empty_guc() -> None:
    """C-09 requires zero rows, never an error, when the GUC is missing —
    and docker/initdb/01-roles.sql ships the GUC preset to the empty string,
    where a bare `''::uuid` raises instead of returning nothing."""
    create = next(
        s for s in partition_rls_statements("memory_item", PID_A) if s.startswith("CREATE POLICY")
    )
    assert "current_setting('tracebed.project_id', true)" in create  # missing_ok
    assert "NULLIF(" in create  # empty-string_ok


@pytest.mark.parametrize("table", PARTITIONED_TABLES)
def test_grants_are_dml_only(table: str) -> None:
    stmts = partition_grant_statements(table, PID_A)
    assert stmts == [
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {partition_name(table, PID_A)} TO tracebed_app"
    ]
    joined = " ".join(stmts).upper()
    for forbidden in ("ALL PRIVILEGES", "TRUNCATE", "REFERENCES", "TRIGGER", "CREATE"):
        assert forbidden not in joined


def test_memory_item_gets_both_retrieval_indexes() -> None:
    stmts = " | ".join(partition_index_statements("memory_item", PID_A))
    assert "USING hnsw (embedding halfvec_cosine_ops)" in stmts
    assert "USING bm25 (content)" in stmts


def test_index_statements_are_idempotent_and_scoped_to_the_partition() -> None:
    for table in PARTITIONED_TABLES:
        name = partition_name(table, PID_A)
        for stmt in partition_index_statements(table, PID_A):
            assert stmt.startswith("CREATE INDEX IF NOT EXISTS ")
            # Never build an index on the parent: that takes an ACCESS
            # EXCLUSIVE lock across every project at once.
            assert f" ON {name} " in stmt


# --------------------------------------------------------------------------- #
# Offline — partitions.py against a recording connection
# --------------------------------------------------------------------------- #


class _FakeCursor:
    """Records SQL and answers the three catalog queries partitions.py runs."""

    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self._result: list[tuple[Any, ...]] = []
        self.closed = False

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        self.closed = True

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> None:
        self._conn.executed.append((sql, params))
        if sql.startswith("SELECT project_id FROM project"):
            self._result = [(pid,) for pid in self._conn.live_project_ids]
        elif "to_regclass" in sql and "pg_inherits" in sql:
            name = (params or {})["name"]
            self._result = [(name in self._conn.attached_partitions,)]
        elif "to_regclass" in sql:
            name = (params or {})["name"]
            self._result = [(name in self._conn.existing_partitions,)]
        else:
            self._result = []

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._result)


class _FakeTransaction:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def __enter__(self) -> _FakeTransaction:
        self._conn.executed.append(("BEGIN", None))
        self._conn.open_transactions += 1
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._conn.open_transactions -= 1
        self._conn.executed.append(("ROLLBACK" if exc_type else "COMMIT", None))


class _FakeConn:
    def __init__(
        self,
        *,
        live_project_ids: list[UUID] | None = None,
        existing_partitions: set[str] | None = None,
        attached_partitions: set[str] | None = None,
    ) -> None:
        self.executed: list[tuple[str, dict[str, Any] | None]] = []
        self.live_project_ids = live_project_ids or []
        self.existing_partitions = existing_partitions
        self.attached_partitions = attached_partitions
        self.open_transactions = 0

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    @property
    def statements(self) -> list[str]:
        return [sql for sql, _ in self.executed]


def _conn_with_all_partitions(project_ids: list[ProjectId]) -> _FakeConn:
    existing = {
        partition_name(table, pid) for table in PARTITIONED_TABLES for pid in project_ids
    }
    return _FakeConn(existing_partitions=existing, attached_partitions=set(existing))


@pytest.mark.parametrize("table", PARTITIONED_TABLES)
def test_create_project_partitions_secures_every_table(table: str) -> None:
    """Invariant 4 is only as good as its weakest partition: one table left
    without ENABLE/FORCE/policy is a whole class of rows readable without a
    scope. Asserted per table so a failure names the table."""
    conn = _FakeConn()
    partitions_mod.create_project_partitions(conn, PID_A)  # type: ignore[arg-type]
    stmts = conn.statements
    name = partition_name(table, PID_A)
    assert create_partition_sql(table, PID_A) in stmts
    for stmt in partition_rls_statements(table, PID_A):
        assert stmt in stmts, f"{table}: missing {stmt!r}"
    for stmt in partition_grant_statements(table, PID_A):
        assert stmt in stmts, f"{table}: missing {stmt!r}"
    for stmt in partition_index_statements(table, PID_A):
        assert stmt in stmts, f"{table}: missing {stmt!r}"
    # The partition must exist before RLS is applied to it.
    assert stmts.index(create_partition_sql(table, PID_A)) < stmts.index(
        f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY"
    )


def test_create_project_partitions_is_one_transaction() -> None:
    """A half-provisioned project is a project whose data is partly
    unprotected; PHASE-0 Task 6 requires all-or-nothing."""
    conn = _FakeConn()
    partitions_mod.create_project_partitions(conn, PID_A)  # type: ignore[arg-type]
    assert conn.statements.count("BEGIN") == 1
    assert conn.statements.count("COMMIT") == 1
    assert conn.statements[0] == "BEGIN"
    assert conn.statements[-1] == "COMMIT"
    assert conn.open_transactions == 0


def test_create_project_partitions_touches_only_this_projects_partitions() -> None:
    conn = _FakeConn()
    partitions_mod.create_project_partitions(conn, PID_A)  # type: ignore[arg-type]
    other = PID_B.value.hex
    assert not any(other in sql for sql in conn.statements)


def test_drop_project_detaches_and_drops_all_thirteen_in_one_transaction() -> None:
    conn = _conn_with_all_partitions([PID_A])
    partitions_mod.drop_project(conn, PID_A)  # type: ignore[arg-type]
    stmts = conn.statements
    assert stmts.count("BEGIN") == 1
    assert stmts[-1] == "COMMIT"
    for table in PARTITIONED_TABLES:
        name = partition_name(table, PID_A)
        assert f"ALTER TABLE {table} DETACH PARTITION {name}" in stmts
        assert f"DROP TABLE IF EXISTS {name}" in stmts
        assert stmts.index(f"ALTER TABLE {table} DETACH PARTITION {name}") < stmts.index(
            f"DROP TABLE IF EXISTS {name}"
        )
    assert not any(PID_B.value.hex in sql for sql in stmts)


def test_drop_project_tolerates_a_missing_partition() -> None:
    """Erasure must not be blocked by a project provisioned before a table
    existed: a project that cannot be deleted is a compliance failure."""
    existing = {
        partition_name(t, PID_A) for t in PARTITIONED_TABLES if t != "blackboard_entry"
    }
    conn = _FakeConn(existing_partitions=existing, attached_partitions=set(existing))
    partitions_mod.drop_project(conn, PID_A)  # type: ignore[arg-type]
    stmts = conn.statements
    missing = partition_name("blackboard_entry", PID_A)
    assert f"DROP TABLE IF EXISTS {missing}" not in stmts
    assert f"DROP TABLE IF EXISTS {partition_name('memory_item', PID_A)}" in stmts


def test_drop_project_skips_detach_for_an_orphaned_partition() -> None:
    """A partition already detached by a half-finished earlier drop must
    still be dropped — DETACHing it again would abort the transaction."""
    existing = {partition_name(t, PID_A) for t in PARTITIONED_TABLES}
    attached = existing - {partition_name("memory_item", PID_A)}
    conn = _FakeConn(existing_partitions=existing, attached_partitions=attached)
    partitions_mod.drop_project(conn, PID_A)  # type: ignore[arg-type]
    stmts = conn.statements
    assert (
        f"ALTER TABLE memory_item DETACH PARTITION {partition_name('memory_item', PID_A)}"
        not in stmts
    )
    assert f"DROP TABLE IF EXISTS {partition_name('memory_item', PID_A)}" in stmts


def test_ensure_schema_current_skips_soft_deleted_projects() -> None:
    """`drop_project` deletes partitions but PLAN.md §5 keeps the registry
    row (deleted_at). An unfiltered sweep re-creates writable, RLS-enabled
    storage for a tenant whose data was erased."""
    conn = _FakeConn(live_project_ids=[PID_A.value])
    partitions_mod.ensure_schema_current(conn)  # type: ignore[arg-type]
    select = next(s for s in conn.statements if s.startswith("SELECT project_id FROM project"))
    assert "deleted_at IS NULL" in select
    assert "status <> 'deleted'" in select
    assert any(PID_A.value.hex in s for s in conn.statements)


def test_ensure_schema_current_reapplies_the_same_ddl_as_creation() -> None:
    """The whole point of ddl.py: a partition created before a migration and
    one created after must end up with identical RLS, grants and indexes."""
    created = _FakeConn()
    partitions_mod.create_project_partitions(created, PID_A)  # type: ignore[arg-type]
    swept = _FakeConn(live_project_ids=[PID_A.value])
    partitions_mod.ensure_schema_current(swept)  # type: ignore[arg-type]

    ddl_only = [s for s in created.statements if s not in ("BEGIN", "COMMIT")]
    swept_ddl = [
        s
        for s in swept.statements
        if s not in ("BEGIN", "COMMIT") and not s.startswith("SELECT project_id FROM project")
    ]
    assert ddl_only == swept_ddl


def test_ensure_schema_current_uses_one_transaction_per_project() -> None:
    conn = _FakeConn(live_project_ids=[PID_A.value, PID_B.value])
    partitions_mod.ensure_schema_current(conn)  # type: ignore[arg-type]
    assert conn.statements.count("BEGIN") == 2
    assert conn.statements.count("COMMIT") == 2
    assert conn.open_transactions == 0


# --------------------------------------------------------------------------- #
# Integration
# --------------------------------------------------------------------------- #

# One valid row per partitioned table, so "RLS returns zero rows" is a claim
# about a database that actually has rows. %(pid)s is the project uuid.
_SEED_ROWS: dict[str, str] = {
    "memory_item": (
        "INSERT INTO memory_item (id, project_id, scope_type, mem_type, kind, lane,"
        " trust_tier, status, content, content_hash, token_count, provenance,"
        " scan_verdict_id) VALUES (gen_random_uuid(), %(pid)s, 'project_shared',"
        " 'lesson', 'note', 'operational', 'B', 'quarantined', 'seed', 'h', 1,"
        " '{}'::jsonb, gen_random_uuid())"
    ),
    "memory_link": (
        "INSERT INTO memory_link (project_id, src_id, dst_id, relation)"
        " VALUES (%(pid)s, gen_random_uuid(), gen_random_uuid(), 'related')"
    ),
    "derived_state": (
        "INSERT INTO derived_state (project_id, agent_type_id, key, version, value)"
        " VALUES (%(pid)s, gen_random_uuid(), 'seed', 1, '{}'::jsonb)"
    ),
    "trace_index": (
        "INSERT INTO trace_index (run_id, project_id, agent_type_id, submitter_principal,"
        " input_signature_hash, instrumentation_source)"
        " VALUES (gen_random_uuid(), %(pid)s, gen_random_uuid(), gen_random_uuid(),"
        " '\\x00'::bytea, 'sdk')"
    ),
    "trace_subject": (
        "INSERT INTO trace_subject (run_id, project_id, subject_tag)"
        " VALUES (gen_random_uuid(), %(pid)s, 'user:seed')"
    ),
    "subject_key": (
        "INSERT INTO subject_key (project_id, subject_tag, key_id, wrapped_kek)"
        " VALUES (%(pid)s, 'user:seed', gen_random_uuid(), '\\x00'::bytea)"
    ),
    "outcome_event": (
        "INSERT INTO outcome_event (event_id, run_id, project_id, principal_id, adapter, r)"
        " VALUES (gen_random_uuid(), gen_random_uuid(), %(pid)s, gen_random_uuid(),"
        " 'verdict', 1.0)"
    ),
    "injection_log": (
        "INSERT INTO injection_log (run_id, project_id, memory_id, slot, score, tokens)"
        " VALUES (gen_random_uuid(), %(pid)s, gen_random_uuid(), 'fact', 0.5, 10)"
    ),
    "retrieval_event": (
        "INSERT INTO retrieval_event (run_id, project_id, outcome_code, latency_ms, arm)"
        " VALUES (gen_random_uuid(), %(pid)s, 'empty_result', 5, 'memory_on')"
    ),
    "blackboard_entry": (
        "INSERT INTO blackboard_entry (project_id, run_id, branch_id, author_agent, key)"
        " VALUES (%(pid)s, gen_random_uuid(), 'main', 'seed-agent', 'k')"
    ),
    "invalidation_event": (
        "INSERT INTO invalidation_event (project_id, event_type) VALUES (%(pid)s, 'seed')"
    ),
    "spend_ledger": (
        "INSERT INTO spend_ledger (project_id, day, worker, model_id)"
        " VALUES (%(pid)s, CURRENT_DATE, 'seed', 'm')"
    ),
    "review_queue": "INSERT INTO review_queue (project_id, reason) VALUES (%(pid)s, 'seed')",
}


def _seed_every_table(cur: Any, project_id: ProjectId) -> None:
    """One row per partitioned table for `project_id`, GUC set first."""
    pid = str(project_id.value)
    cur.execute("SELECT set_config('tracebed.project_id', %(pid)s, true)", {"pid": pid})
    for table in PARTITIONED_TABLES:
        cur.execute(_SEED_ROWS[table], {"pid": pid})


def _app_role_conninfo(pg_dsn: str) -> str:
    """`pg_dsn` with the credentials swapped for the app role.

    Uses psycopg's own conninfo parser so this works for both URL and
    keyword-style DSNs — a hand-rolled urlsplit silently produces a broken
    DSN for `host=... dbname=...`, and a broken DSN makes the probe skip
    instead of run.
    """
    from psycopg.conninfo import make_conninfo

    return make_conninfo(pg_dsn, user="tracebed_app", password=_APP_ROLE_PASSWORD)


@pytest.mark.integration
class TestPartitionsIntegration:
    def test_two_projects_isolated_and_drop_is_atomic(
        self, pg_pool: Any, two_projects: tuple[Any, Any]
    ) -> None:
        from tracebed.stores.pg.partitions import drop_project

        scope_a, scope_b = two_projects
        pid_a, pid_b = scope_a.project_id, scope_b.project_id

        with pg_pool.connection() as conn:
            with conn.cursor() as cur:
                for table in PARTITIONED_TABLES:
                    for pid in (pid_a, pid_b):
                        name = partition_name(table, pid)
                        cur.execute("SELECT to_regclass(%s) IS NOT NULL", (name,))
                        row = cur.fetchone()
                        assert row is not None and row[0], f"missing partition {name}"
                _seed_every_table(cur, pid_a)
                _seed_every_table(cur, pid_b)
            conn.commit()

            drop_project(conn, pid_a)
            conn.commit()

            with conn.cursor() as cur:
                for table in PARTITIONED_TABLES:
                    cur.execute(
                        "SELECT to_regclass(%s) IS NOT NULL", (partition_name(table, pid_a),)
                    )
                    row = cur.fetchone()
                    assert row is not None and row[0] is False, (
                        f"{table} partition for project A survived drop_project"
                    )
                    cur.execute(
                        "SELECT to_regclass(%s) IS NOT NULL", (partition_name(table, pid_b),)
                    )
                    row = cur.fetchone()
                    assert row is not None and row[0], (
                        f"{table} partition for project B was dropped alongside A"
                    )

                # B's DATA, not just B's partitions (PHASE-0 Task 6: "insert
                # into each; drop_project removes one ... other intact").
                cur.execute(
                    "SELECT set_config('tracebed.project_id', %s, true)", (str(pid_b.value),)
                )
                for table in PARTITIONED_TABLES:
                    cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed whitelist
                    row = cur.fetchone()
                    assert row is not None and row[0] == 1, f"{table} lost project B's row"
            conn.rollback()

    def test_app_role_without_guc_sees_zero_rows(
        self, pg_dsn: str, pg_pool: Any, two_projects: tuple[Any, Any]
    ) -> None:
        """RLS bypass probe (PLAN.md §2 invariant 4, probe (g)): raw SQL as
        the non-owner app role with no GUC set must return zero rows from
        every partitioned table, never an error and never another project's
        data (contract C-09).

        Seeds a row into every partitioned table for both projects first.
        Without that, `count(*) = 0` is true of an empty table and the probe
        passes against a database with RLS switched off entirely.
        """
        import psycopg

        scope_a, scope_b = two_projects
        with pg_pool.connection() as conn:
            with conn.cursor() as cur:
                _seed_every_table(cur, scope_a.project_id)
                _seed_every_table(cur, scope_b.project_id)
            conn.commit()

        try:
            app_conn = psycopg.connect(_app_role_conninfo(pg_dsn), connect_timeout=2)
        except psycopg.OperationalError as exc:
            # Never interpolate the DSN: it carries the password and this
            # message lands in the gate report and CI logs.
            pytest.skip(
                f"tracebed_app role unreachable ({exc.__class__.__name__}); pg_hba.conf / "
                "compose auth for this role is docker/compose.yaml + docker/initdb's "
                "concern (harness chunk, PHASE-0 Task 1), not migrations'. Set "
                "TB_APP_ROLE_PASSWORD if the deployment rotated it."
            )
        try:
            with app_conn.cursor() as cur:
                for table in PARTITIONED_TABLES:
                    cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed whitelist
                    row = cur.fetchone()
                    assert row is not None and row[0] == 0, (
                        f"{table} leaked {row[0] if row else '?'} rows to tracebed_app "
                        "with no GUC set"
                    )
                app_conn.rollback()

                # ...and the same role WITH the GUC set sees its own project
                # only. Without this half, "zero rows" would also pass if the
                # role simply had no SELECT grant.
                cur.execute(
                    "SELECT set_config('tracebed.project_id', %s, true)",
                    (str(scope_a.project_id.value),),
                )
                for table in PARTITIONED_TABLES:
                    cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed whitelist
                    row = cur.fetchone()
                    assert row is not None and row[0] == 1, (
                        f"{table}: app role with a valid GUC saw {row[0] if row else '?'} "
                        "rows, expected exactly project A's one"
                    )
            app_conn.rollback()
        finally:
            app_conn.close()
