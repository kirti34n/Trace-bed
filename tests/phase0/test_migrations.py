"""tests/phase0/test_migrations.py — PHASE-0 Tasks 5 & 6 (contract §13.2).

Two halves:

* Offline (no database, run on every machine including this one): parse the
  `.sql` files as text — and, where it is cheap, through yoyo's own reader —
  and assert the structural properties PHASE-0.md Tasks 5/6 and
  docs/PHASE0-CONTRACT.md §14 require regardless of a live Postgres: every
  registry/learning-plane table from PLAN.md §5 is present, the isolation
  root on `agent_registration.principal_id` exists, `memory_item.scan_verdict_id`
  is `NOT NULL` with no default (an insert without a `ScanVerdict` must be
  impossible at the schema level), the RLS policy is fail-closed, and the
  migration tree is actually loadable and reversible by yoyo.
* Integration (`@pytest.mark.integration`, needs the compose PG18 stack):
  apply the migrations for real and prove what only a live database can —
  both extensions install, rollback removes the schema (not merely yoyo's
  bookkeeping), a second `agent_registration` for one principal is rejected,
  and a `memory_item` insert with a NULL `scan_verdict_id` is rejected by the
  database itself. Uses the shared `pg_dsn` / `pg_pool` fixtures from
  `tests/phase0/conftest.py` (contract §13.1, owned by the `harness` chunk);
  if that fixture is absent or the database is unreachable, these tests skip
  rather than error — see docs/PHASE0-CONTRACT.md §12.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.phase0

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

MIGRATION_IDS = ("0001_registries", "0002_partitioned", "0003_rls")

REGISTRY_TABLES = (
    "project",
    "principal",
    "agent_type",
    "agent_registration",
    "embedding_model",
    "scoring_epoch",
    "project_config",
    "agent_type_config",
    "killswitch_state",
)

_PARTITIONED_TABLES = (
    "memory_item",
    "memory_link",
    "derived_state",
    "trace_index",
    "trace_subject",
    "subject_key",
    "outcome_event",
    "injection_log",
    "retrieval_event",
    "blackboard_entry",
    "invalidation_event",
    "spend_ledger",
    "review_queue",
)


def _read(name: str) -> str:
    return (MIGRATIONS_DIR / name).read_text(encoding="utf-8")


def _strip_sql_comments(sql: str) -> str:
    """Drop `--` line comments.

    Assertions about what a migration GRANTS or CREATES must read the
    statements, not the prose next to them: these files document their own
    security choices at length, and matching those sentences is how a
    security assertion turns into a tautology.
    """
    return "\n".join(re.sub(r"--.*$", "", line) for line in sql.splitlines())


def _table_block(sql: str, table: str) -> str:
    """Return the text of `CREATE TABLE {table} ( ... )`, paren-balanced.

    A naive regex up to the first `)` breaks on `CHECK (...)` clauses nested
    inside the table body; this walks parens so column/constraint checks
    inside the table definition do not truncate the match early.
    """
    m = re.search(rf"CREATE TABLE\s+{re.escape(table)}\s*\(", sql, re.IGNORECASE)
    assert m, f"CREATE TABLE {table} not found in migration"
    start = m.end() - 1  # index of the opening '('
    depth = 0
    close = start
    for i in range(start, len(sql)):
        if sql[i] == "(":
            depth += 1
        elif sql[i] == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
    # Include anything between the closing ')' of the column list and the
    # statement terminator -- that is where `PARTITION BY LIST (project_id)`
    # lives for partitioned tables.
    terminator = sql.index(";", close)
    return sql[m.start() : terminator + 1]


# --------------------------------------------------------------------------- #
# Offline: the migration tree itself
# --------------------------------------------------------------------------- #


class TestMigrationTree:
    def test_yoyo_can_read_every_migration_and_resolve_dependencies(self) -> None:
        """`read_migrations` raising BadMigration on an unresolvable
        `-- depends:` is the only thing standing between a typo'd dependency
        and migrations applying in the wrong order."""
        from tracebed.stores.pg.migrate import read_all_migrations

        assert [m.id for m in read_all_migrations()] == list(MIGRATION_IDS)

    @pytest.mark.parametrize("migration_id", MIGRATION_IDS)
    def test_every_migration_has_a_rollback_companion(self, migration_id: str) -> None:
        """yoyo treats a missing `<name>.rollback.sql` as "this step has no
        rollback": it un-marks the migration as applied and executes nothing.
        `yoyo rollback` would then report success over a database whose every
        table survived, and the next `apply` would die on "relation already
        exists". PHASE-0 Task 5's proving test is unpassable without these."""
        companion = MIGRATIONS_DIR / f"{migration_id}.rollback.sql"
        assert companion.is_file(), f"{companion.name} missing"
        assert companion.read_text(encoding="utf-8").strip()

    @pytest.mark.parametrize("migration_id", MIGRATION_IDS)
    def test_rollback_has_no_more_statements_than_the_migration(
        self, migration_id: str
    ) -> None:
        """yoyo zips forward and (reversed) rollback statements with
        `zip_longest(fillvalue=None)`. A rollback file with MORE statements
        than its migration produces a step whose *apply* is None, which
        raises `TypeError: 'NoneType' object is not callable` the next time
        the migration is applied."""
        from yoyo.migrations import read_sql_migration

        _, _, forward = read_sql_migration(str(MIGRATIONS_DIR / f"{migration_id}.sql"))
        _, _, backward = read_sql_migration(
            str(MIGRATIONS_DIR / f"{migration_id}.rollback.sql")
        )
        assert backward, f"{migration_id}.rollback.sql parsed to zero statements"
        assert len(backward) <= len(forward)

    def test_rollback_drops_every_table_the_migration_creates(self) -> None:
        """Drift guard: a table added to 0001/0002 without a matching entry
        in its rollback file leaves that table behind on rollback, which the
        offline tests would otherwise never notice."""
        for migration_id in ("0001_registries", "0002_partitioned"):
            created = set(
                re.findall(r"CREATE TABLE\s+(\w+)", _read(f"{migration_id}.sql"), re.IGNORECASE)
            )
            dropped_text = _read(f"{migration_id}.rollback.sql")
            for table in created:
                assert re.search(rf"\b{table}\b", dropped_text), (
                    f"{migration_id}.sql creates {table} but its rollback never drops it"
                )


# --------------------------------------------------------------------------- #
# Offline: 0001_registries.sql
# --------------------------------------------------------------------------- #


class TestRegistriesStructure:
    def test_extensions_declared(self) -> None:
        sql = _read("0001_registries.sql")
        assert re.search(r"CREATE EXTENSION.*\bvector\b", sql, re.IGNORECASE)
        assert re.search(r"CREATE EXTENSION.*\bpg_textsearch\b", sql, re.IGNORECASE)

    @pytest.mark.parametrize("table", REGISTRY_TABLES)
    def test_registry_table_present(self, table: str) -> None:
        sql = _read("0001_registries.sql")
        assert re.search(rf"CREATE TABLE\s+{table}\b", sql, re.IGNORECASE), table

    def test_agent_registration_principal_id_is_the_isolation_root(self) -> None:
        """UNIQUE(principal_id) is the isolation root (PLAN.md §5, D-017)."""
        block = _table_block(_read("0001_registries.sql"), "agent_registration")
        assert re.search(r"principal_id\s+uuid\s+PRIMARY KEY", block, re.IGNORECASE), (
            "agent_registration.principal_id must be PRIMARY KEY (PK implies "
            "UNIQUE + NOT NULL, strictly satisfying UNIQUE(principal_id))"
        )
        assert re.search(r"project_id\s+uuid\s+NOT NULL", block, re.IGNORECASE)
        assert re.search(r"agent_type_id\s+uuid\s+NOT NULL", block, re.IGNORECASE)

    def test_principal_external_ref_is_globally_unique(self) -> None:
        """`Repo.get_principal_by_external_ref` (contract §5.1) takes no
        `kind`, so a per-kind uniqueness constraint would allow two rows one
        credential lookup cannot choose between — ambiguity at the root of
        scope derivation (invariant 4)."""
        block = _table_block(_read("0001_registries.sql"), "principal")
        assert re.search(r"UNIQUE\s*\(\s*external_ref\s*\)", block, re.IGNORECASE), block

    def test_registries_are_not_partitioned(self) -> None:
        sql = _read("0001_registries.sql")
        assert "PARTITION BY" not in sql.upper()


# --------------------------------------------------------------------------- #
# Offline: 0002_partitioned.sql
# --------------------------------------------------------------------------- #


class TestPartitionedStructure:
    @pytest.mark.parametrize("table", _PARTITIONED_TABLES)
    def test_learning_plane_table_present_and_partitioned(self, table: str) -> None:
        sql = _read("0002_partitioned.sql")
        block = _table_block(sql, table)
        assert re.search(
            r"PARTITION BY LIST\s*\(\s*project_id\s*\)", block, re.IGNORECASE
        ), f"{table} must be PARTITION BY LIST (project_id)"

    @pytest.mark.parametrize("table", _PARTITIONED_TABLES)
    def test_primary_key_contains_project_id(self, table: str) -> None:
        sql = _read("0002_partitioned.sql")
        block = _table_block(sql, table)
        pk = re.search(r"PRIMARY KEY\s*\(([^)]*)\)", block, re.IGNORECASE)
        assert pk, f"{table} declares no PRIMARY KEY"
        cols = [c.strip() for c in pk.group(1).split(",")]
        assert cols[0] == "project_id", f"{table} PK does not start with project_id: {cols}"

    def test_all_thirteen_learning_plane_tables_accounted_for(self) -> None:
        sql = _read("0002_partitioned.sql")
        declared = set(
            re.findall(
                r"CREATE TABLE\s+(\w+)\s*\([\s\S]*?PARTITION BY LIST\s*\(\s*project_id\s*\)",
                sql,
                re.IGNORECASE,
            )
        )
        assert declared == set(_PARTITIONED_TABLES)

    def test_unpartitioned_queue_tables_present(self) -> None:
        sql = _read("0002_partitioned.sql")
        assert re.search(r"CREATE TABLE\s+work_queue\b", sql, re.IGNORECASE)
        assert re.search(r"CREATE TABLE\s+dead_letter\b", sql, re.IGNORECASE)
        # neither queue table is partitioned (contract §5.3)
        wq_block = _table_block(sql, "work_queue")
        dl_block = _table_block(sql, "dead_letter")
        assert "PARTITION BY" not in wq_block.upper()
        assert "PARTITION BY" not in dl_block.upper()

    def test_memory_item_scan_verdict_id_is_insert_blocking(self) -> None:
        """An insert without a ScanVerdict must be impossible at the schema
        level (contract §1, PHASE-0 Task 6) -- NOT NULL with no default."""
        block = _table_block(_read("0002_partitioned.sql"), "memory_item")
        col_line = re.search(r"scan_verdict_id\s+uuid[^,]*,", block, re.IGNORECASE)
        assert col_line, "scan_verdict_id column not found"
        assert "NOT NULL" in col_line.group(0).upper()
        assert "DEFAULT" not in col_line.group(0).upper()

    def test_memory_item_embedding_stamp_check_is_the_paired_nullability_rule(self) -> None:
        """The embedding and its model stamp must be present or absent
        together: a vector with no `(model_id, model_version)` is a row no
        re-embed migration can ever find (D-007), and a stamp with no vector
        is a lie about what was indexed. Asserted as the specific constraint,
        not "the block contains some CHECK" — memory_item has six of those."""
        block = _table_block(_read("0002_partitioned.sql"), "memory_item")
        normalised = " ".join(block.split()).lower()
        both_null = (
            "(embedding is null and embedding_model_id is null "
            "and embedding_model_version is null)"
        )
        both_set = (
            "(embedding is not null and embedding_model_id is not null "
            "and embedding_model_version is not null)"
        )
        assert both_null in normalised, "missing the all-NULL half of the embedding-stamp CHECK"
        assert both_set in normalised, "missing the all-NOT-NULL half of the embedding-stamp CHECK"
        assert f"{both_null} or {both_set}" in normalised

    def test_memory_item_status_domain_matches_the_state_machine(self) -> None:
        """The nine statuses of the one state machine (PLAN.md §5). A status
        the schema accepts but the machine does not know is a row nothing can
        legally transition."""
        from tracebed.domain.state_machine import Status

        block = _table_block(_read("0002_partitioned.sql"), "memory_item")
        check = re.search(r"status\s+text\s+NOT NULL\s+CHECK\s*\(status IN \(([^)]*)\)",
                          block, re.IGNORECASE)
        assert check, "memory_item.status has no CHECK constraint"
        allowed = {v.strip().strip("'") for v in check.group(1).split(",")}
        assert allowed == {s.value for s in Status}

    def test_outcome_event_pk_and_principal(self) -> None:
        block = _table_block(_read("0002_partitioned.sql"), "outcome_event")
        pk = re.search(r"PRIMARY KEY\s*\(([^)]*)\)", block, re.IGNORECASE)
        assert pk
        cols = [c.strip() for c in pk.group(1).split(",")]
        assert cols == ["project_id", "event_id"]
        assert re.search(r"principal_id\s+uuid\s+NOT NULL", block, re.IGNORECASE)

    def test_outcome_event_has_no_weight_column(self) -> None:
        """Invariant 8: callers never supply weights and `w` is never stored
        as caller data — it is derived from the adapter class (C-10)."""
        block = _table_block(_read("0002_partitioned.sql"), "outcome_event").lower()
        assert not re.search(r"^\s*w\s+(double|float|numeric|real)", block, re.MULTILINE)
        assert "weight" not in block

    def test_trace_index_required_columns(self) -> None:
        block = _table_block(_read("0002_partitioned.sql"), "trace_index")
        assert re.search(r"submitter_principal\s+uuid\s+NOT NULL", block, re.IGNORECASE)
        assert re.search(r"input_signature_hash\s+bytea\s+NOT NULL", block, re.IGNORECASE)
        assert "instrumentation_source" in block
        assert "arm" in block
        assert re.search(r"outcome_status[\s\S]*incomplete", block, re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Offline: 0003_rls.sql
# --------------------------------------------------------------------------- #


class TestRlsStructure:
    @pytest.mark.parametrize("table", _PARTITIONED_TABLES)
    def test_force_row_level_security(self, table: str) -> None:
        sql = _read("0003_rls.sql")
        assert re.search(
            rf"ALTER TABLE\s+{table}\s+ENABLE ROW LEVEL SECURITY", sql, re.IGNORECASE
        ), f"{table} missing ENABLE ROW LEVEL SECURITY"
        assert re.search(
            rf"ALTER TABLE\s+{table}\s+FORCE ROW LEVEL SECURITY", sql, re.IGNORECASE
        ), f"{table} missing FORCE ROW LEVEL SECURITY"

    @pytest.mark.parametrize("table", _PARTITIONED_TABLES)
    def test_policy_is_fail_closed_for_unset_and_empty_guc(self, table: str) -> None:
        """A missing GUC must yield zero rows, never an error a caller could
        catch and route around (contract C-09, PHASE-0 Task 6's proving
        test). `missing_ok=true` covers "unset"; `NULLIF(..., '')` covers
        "preset to empty", which is what docker/initdb/01-roles.sql's
        `ALTER DATABASE ... SET tracebed.project_id TO ''` actually produces
        — and where a bare `''::uuid` raises on every row of every query."""
        sql = _read("0003_rls.sql")
        pattern = (
            rf"CREATE POLICY \w+ ON {table}\s+USING \(project_id = "
            r"NULLIF\(current_setting\('tracebed\.project_id',\s*true\),\s*''\)::uuid\)"
        )
        assert re.search(pattern, sql, re.IGNORECASE), table

    def test_every_policy_uses_the_same_predicate(self) -> None:
        predicates = {
            " ".join(p.split())
            for p in re.findall(
                r"CREATE POLICY \w+ ON \w+\s+USING \(([\s\S]*?)\);", _read("0003_rls.sql")
            )
        }
        assert len(predicates) == 1, predicates
        assert len(re.findall(r"CREATE POLICY ", _read("0003_rls.sql"))) == 13

    def test_app_role_is_not_owner_and_has_no_bypassrls(self) -> None:
        sql = _strip_sql_comments(_read("0003_rls.sql"))
        assert "tracebed_app" in sql
        # Any BYPASSRLS/SUPERUSER token must be the negated form. A mutation
        # that grants the attribute at CREATE time and negates it later would
        # otherwise slip past a bare "NOBYPASSRLS is mentioned" assertion.
        for attr in ("BYPASSRLS", "SUPERUSER", "CREATEROLE", "CREATEDB", "REPLICATION"):
            for match in re.finditer(rf"\b(NO)?{attr}\b", sql):
                assert match.group(1) == "NO", f"{attr} granted without NO prefix"
        assert not re.search(r"GRANT\s+(?:ALL|CREATE|TRUNCATE)\b[^;]*tracebed_app", sql,
                             re.IGNORECASE)

    def test_migration_ships_no_credential(self) -> None:
        """A password in a migration is a checked-in secret AND a second
        source of truth for a credential docker/initdb/01-roles.sql already
        owns — the two silently disagreed before this assertion existed."""
        sql = _strip_sql_comments(_read("0003_rls.sql"))
        assert not re.search(r"\bPASSWORD\b\s*'", sql, re.IGNORECASE)
        assert re.search(r"CREATE ROLE tracebed_app[^;]*NOLOGIN", sql, re.IGNORECASE)

    def test_yoyo_bookkeeping_is_not_writable_by_the_app_role(self) -> None:
        """`GRANT ... ON ALL TABLES IN SCHEMA public` sweeps up yoyo's own
        `_yoyo_*` tables. The application must not be able to rewrite the
        record of which security migrations have been applied."""
        sql = _strip_sql_comments(_read("0003_rls.sql"))
        assert re.search(r"REVOKE ALL PRIVILEGES ON [^;]*FROM tracebed_app", sql, re.IGNORECASE)
        assert "_yoyo" in sql


# --------------------------------------------------------------------------- #
# Integration: apply against a live PG18
# --------------------------------------------------------------------------- #

_ALL_MIGRATION_TABLES = REGISTRY_TABLES + _PARTITIONED_TABLES + ("work_queue", "dead_letter")


def _existing_tables(conn: Any) -> set[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
        return {row[0] for row in cur.fetchall()}


@pytest.mark.integration
class TestMigrationsIntegration:
    def test_apply_then_rollback_clean(self, pg_dsn: str, pg_pool: Any) -> None:
        """Task 5's proving test. Asserts the SCHEMA, not yoyo's bookkeeping:
        a rollback that only deletes rows from `_yoyo_migration` looks
        identical from `current_revision()` and leaves every table standing.
        """
        from tracebed.stores.pg.migrate import (
            apply_migrations,
            current_revision,
            rollback_migrations,
        )

        apply_migrations(pg_dsn)
        applied = set(current_revision(pg_dsn))
        assert applied == set(MIGRATION_IDS)

        with pg_pool.connection() as conn:
            present = _existing_tables(conn)
        assert set(_ALL_MIGRATION_TABLES) <= present

        rolled_back = rollback_migrations(pg_dsn, all=True)
        assert set(rolled_back) == applied
        assert current_revision(pg_dsn) == []

        with pg_pool.connection() as conn:
            after = _existing_tables(conn)
        assert not (set(_ALL_MIGRATION_TABLES) & after), (
            "rollback un-marked the migrations but left tables behind: "
            f"{sorted(set(_ALL_MIGRATION_TABLES) & after)}"
        )

        # Leave the database in the applied state for the rest of the
        # integration suite (pg_pool applies migrations once per session,
        # per contract §13.1 -- this test must not leave it torn down).
        # A re-apply that succeeds is also the proof that the rollback was
        # complete enough to be idempotent.
        reapplied = apply_migrations(pg_dsn)
        assert set(reapplied) == applied

    def test_extensions_installed(self, pg_pool: Any) -> None:
        with pg_pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT extname FROM pg_extension")
            names = {row[0] for row in cur.fetchall()}
        assert "vector" in names
        assert "pg_textsearch" in names

    def test_app_role_attributes(self, pg_pool: Any) -> None:
        """Invariant 4's backstop is void if the role the service connects as
        can ignore policies. Cheap to check, catastrophic to get wrong."""
        with pg_pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication "
                "FROM pg_roles WHERE rolname = 'tracebed_app'"
            )
            row = cur.fetchone()
        assert row is not None, "tracebed_app role does not exist"
        assert row == (False, False, False, False, False), row

    def test_app_role_does_not_own_the_learning_plane(self, pg_pool: Any) -> None:
        """FORCE ROW LEVEL SECURITY does not apply to a table's owner unless
        forced, and ownership also implies DDL rights (DROP POLICY)."""
        with pg_pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = current_schema() AND tableowner = 'tracebed_app'"
            )
            owned = {row[0] for row in cur.fetchall()}
        assert not owned, f"tracebed_app owns tables: {sorted(owned)}"

    def test_duplicate_agent_registration_rejected(self, pg_pool: Any) -> None:
        import psycopg

        with pg_pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO project (name) VALUES ('mig-test-dup') RETURNING project_id"
                )
                row = cur.fetchone()
                assert row is not None
                project_id = row[0]
                cur.execute(
                    "INSERT INTO principal (kind, external_ref) "
                    "VALUES ('api_key', 'mig-test-dup-principal') RETURNING principal_id"
                )
                row = cur.fetchone()
                assert row is not None
                principal_id = row[0]
                cur.execute(
                    "INSERT INTO agent_type (project_id, name) VALUES (%s, 'agent') "
                    "RETURNING agent_type_id",
                    (project_id,),
                )
                row = cur.fetchone()
                assert row is not None
                agent_type_id = row[0]
                cur.execute(
                    "INSERT INTO agent_registration (principal_id, project_id, agent_type_id) "
                    "VALUES (%s, %s, %s)",
                    (principal_id, project_id, agent_type_id),
                )
            conn.commit()

            with pytest.raises(psycopg.errors.UniqueViolation), conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO agent_registration "
                    "(principal_id, project_id, agent_type_id) VALUES (%s, %s, %s)",
                    (principal_id, project_id, agent_type_id),
                )
            conn.rollback()

    def test_memory_item_insert_without_scan_verdict_fails(
        self, pg_pool: Any, two_projects: tuple[Any, Any]
    ) -> None:
        import psycopg

        scope_a, _ = two_projects
        with pg_pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT set_config('tracebed.project_id', %s, true)",
                    (str(scope_a.project_id.value),),
                )
                with pytest.raises(psycopg.errors.NotNullViolation):
                    cur.execute(
                        """
                        INSERT INTO memory_item (
                            id, project_id, scope_type, mem_type, kind, lane,
                            trust_tier, status, content, content_hash, token_count,
                            provenance
                        ) VALUES (
                            gen_random_uuid(), %s, 'project_shared', 'lesson', 'note',
                            'operational', 'B', 'quarantined', 'x', 'x', 1, '{}'::jsonb
                        )
                        """,
                        (str(scope_a.project_id.value),),
                    )
            conn.rollback()
