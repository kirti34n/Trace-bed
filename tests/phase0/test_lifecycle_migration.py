"""`migrations/0004_lifecycle.sql` — structural proof, offline (docs/FIDELITY-AUDIT.md M1;
PLAN.md §11 M1).

Mirrors the offline half of `tests/phase0/test_migrations.py` (same paren-balanced
`CREATE TABLE` extraction, same "read the .sql as text" approach — there is no Postgres on
this machine) applied to 0004 specifically. Deliberately self-contained rather than
importing that file's `MIGRATION_IDS`/`_PARTITIONED_TABLES` constants: those are owned by a
different chunk and this file must not couple to them changing.

CONTRACT GAP (reported, not deviated from): adding `0004_lifecycle.sql` makes
`stores.pg.migrate.read_all_migrations()` — a directory scan — return four migration ids.
`tests/phase0/test_migrations.py::TestMigrationTree
.test_yoyo_can_read_every_migration_and_resolve_dependencies` asserts that result equals a
hardcoded 3-tuple (`MIGRATION_IDS = ("0001_registries", "0002_partitioned", "0003_rls")`, that
file's line 38) and is NOT in this chunk's file list. That one test regresses the moment this
migration exists; `test_yoyo_can_load_every_migration_including_lifecycle` below proves the
loader itself works correctly (four ids, in dependency order, `0004_lifecycle` last) so the
fix on the other file's side is mechanical: append `"0004_lifecycle"` to its tuple. Every
other test in that file reads one specifically-named `.sql` file rather than scanning the
migrations directory (verified by inspection of every `MIGRATIONS_DIR` / `_read` call there)
and is unaffected by this migration's existence.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.phase0

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

# The nine `Status` values (domain/state_machine.py), duplicated here as plain strings
# deliberately: this file proves the SQL text matches PLAN.md §5's enum, not that it matches
# whatever `Status` happens to contain today — the two are supposed to agree, and a test that
# imported `Status` to build this list could never notice them drifting apart.
_STATUSES = (
    "quarantined", "candidate", "validated", "superseded",
    "stale", "retired", "archived", "pinned", "tombstoned",
)

_ISOLATION_PREDICATE = (
    "project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid"
)


def _read(name: str) -> str:
    return (MIGRATIONS_DIR / name).read_text(encoding="utf-8")


def _strip_sql_comments(sql: str) -> str:
    return "\n".join(re.sub(r"--.*$", "", line) for line in sql.splitlines())


def _table_block(sql: str, table: str) -> str:
    """Paren-balanced `CREATE TABLE {table} ( ... )` text, identical approach to
    `test_migrations.py::_table_block` (duplicated rather than imported — see module
    docstring on why this file does not import from that one)."""
    m = re.search(rf"CREATE TABLE\s+{re.escape(table)}\s*\(", sql, re.IGNORECASE)
    assert m, f"CREATE TABLE {table} not found in migration"
    start = m.end() - 1
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
    terminator = sql.index(";", close)
    return sql[m.start() : terminator + 1]


FORWARD_SQL = _read("0004_lifecycle.sql")
ROLLBACK_SQL = _read("0004_lifecycle.rollback.sql")
HISTORY_BLOCK = _table_block(FORWARD_SQL, "memory_status_log")


# --------------------------------------------------------------------------- #
# The migration pair itself
# --------------------------------------------------------------------------- #


class TestMigrationPairExists:
    def test_forward_and_rollback_files_exist_and_are_non_empty(self) -> None:
        assert (MIGRATIONS_DIR / "0004_lifecycle.sql").is_file()
        assert (MIGRATIONS_DIR / "0004_lifecycle.rollback.sql").is_file()
        assert FORWARD_SQL.strip()
        assert ROLLBACK_SQL.strip()

    def test_depends_on_0003_rls(self) -> None:
        """yoyo's own dependency-ordering directive — without it, 0004 could apply before
        0003's RLS role/grants exist, which is the same "migration ran but nothing gates it
        yet" hazard 0003 itself warns about for FORCE RLS."""
        first_line = FORWARD_SQL.strip().splitlines()[0]
        assert first_line.strip() == "-- depends: 0003_rls"

    def test_yoyo_can_load_every_migration_including_lifecycle(self) -> None:
        """The loader-level proof for this file's own CONTRACT GAP note above: four ids,
        dependency-ordered, `0004_lifecycle` last. `test_migrations.py`'s hardcoded 3-tuple
        assertion is what needs a one-line update elsewhere; this is not that test."""
        from tracebed.stores.pg.migrate import read_all_migrations

        ids = [m.id for m in read_all_migrations()]
        assert ids == ["0001_registries", "0002_partitioned", "0003_rls", "0004_lifecycle"]

    def test_rollback_has_no_more_statements_than_the_migration(self) -> None:
        """Same proving mechanism as `test_migrations.py`'s companion test: yoyo pairs
        forward/rollback statements positionally (`zip_longest`), so a rollback with MORE
        statements than its migration produces a step whose `apply` is `None` and crashes the
        next `apply_migrations()` call."""
        from yoyo.migrations import read_sql_migration

        _, _, forward = read_sql_migration(str(MIGRATIONS_DIR / "0004_lifecycle.sql"))
        _, _, backward = read_sql_migration(str(MIGRATIONS_DIR / "0004_lifecycle.rollback.sql"))
        assert backward, "0004_lifecycle.rollback.sql parsed to zero statements"
        assert len(backward) <= len(forward)

    def test_rollback_drops_memory_status_log_and_the_epoch_id_column(self) -> None:
        assert re.search(r"\bmemory_status_log\b", ROLLBACK_SQL)
        assert re.search(r"DROP\s+COLUMN.*epoch_id", ROLLBACK_SQL, re.IGNORECASE)


# --------------------------------------------------------------------------- #
# memory_status_log — the same three assertions test_migrations.py makes for every
# table in 0002_partitioned.sql, applied here (module docstring).
# --------------------------------------------------------------------------- #


class TestMemoryStatusHistoryStructure:
    def test_is_list_partitioned_by_project_id(self) -> None:
        assert re.search(
            r"PARTITION BY LIST\s*\(\s*project_id\s*\)", HISTORY_BLOCK, re.IGNORECASE
        ), "memory_status_log must be PARTITION BY LIST (project_id)"

    def test_primary_key_starts_with_project_id(self) -> None:
        pk = re.search(r"PRIMARY KEY\s*\(([^)]*)\)", HISTORY_BLOCK, re.IGNORECASE)
        assert pk, "memory_status_log declares no PRIMARY KEY"
        cols = [c.strip() for c in pk.group(1).split(",")]
        assert cols[0] == "project_id", f"PK does not start with project_id: {cols}"

    def test_force_row_level_security(self) -> None:
        assert re.search(
            r"ALTER TABLE\s+memory_status_log\s+FORCE ROW LEVEL SECURITY",
            FORWARD_SQL,
            re.IGNORECASE,
        ), "memory_status_log must FORCE ROW LEVEL SECURITY (owner/superuser backstop)"

    def test_enable_row_level_security_precedes_force(self) -> None:
        enable = re.search(
            r"ALTER TABLE\s+memory_status_log\s+ENABLE ROW LEVEL SECURITY",
            FORWARD_SQL,
            re.IGNORECASE,
        )
        force = re.search(
            r"ALTER TABLE\s+memory_status_log\s+FORCE ROW LEVEL SECURITY",
            FORWARD_SQL,
            re.IGNORECASE,
        )
        assert enable and force
        assert enable.start() < force.start()

    def test_isolation_policy_predicate_is_byte_identical_to_the_established_form(self) -> None:
        """Must never diverge from 0003_rls.sql's / stores/pg/ddl.py's `_ISOLATION_PREDICATE`
        (that module's own comment: "the two must never diverge"). A policy reading
        `current_setting('tracebed.project_id')::uuid` without `, true` / `NULLIF` raises
        instead of returning zero rows on an unset GUC — the exact regression 0003's header
        documents at length."""
        policy = re.search(
            r"CREATE POLICY\s+memory_status_log_isolation\s+ON\s+memory_status_log\s+"
            r"USING\s*\(([^;]*)\)\s*;",
            _strip_sql_comments(FORWARD_SQL),
            re.IGNORECASE,
        )
        assert policy, "memory_status_log_isolation policy not found"
        predicate = " ".join(policy.group(1).split())
        assert predicate == _ISOLATION_PREDICATE

    def test_from_status_and_to_status_check_constraints_cover_every_status(self) -> None:
        for column in ("from_status", "to_status"):
            # `[^)]*\)\)` stops at the first `))`, which closes both the `IN (...)` list and
            # the `CHECK (...)` wrapping it -- a naive stop-at-first-comma regex breaks
            # because the status list itself is comma-separated.
            col_line = re.search(rf"{column}\s+text[^)]*\)\)", HISTORY_BLOCK, re.IGNORECASE)
            assert col_line, f"{column} column not found"
            for status in _STATUSES:
                assert f"'{status}'" in col_line.group(0), f"{column} CHECK missing {status!r}"

    def test_from_status_may_not_equal_to_status(self) -> None:
        assert re.search(r"CHECK\s*\(\s*from_status\s*<>\s*to_status\s*\)", HISTORY_BLOCK, re.IGNORECASE)

    def test_no_foreign_key_to_memory_item(self) -> None:
        """Same convention every table in 0002_partitioned.sql follows (that migration's own
        header comment): a partitioned child never FKs to another partitioned parent —
        `stores.pg.partitions.drop_project` (DETACH+DROP), not `ON DELETE CASCADE`, is the
        project-deletion path, and cross-partition FKs only add planner/lock overhead."""
        assert "REFERENCES" not in HISTORY_BLOCK.upper()

    def test_declares_no_index(self) -> None:
        """Per-partition indexes are `stores/pg/ddl.py`'s job (0002_partitioned.sql creates
        none either — verified by this repo's own convention, not asserted a priori); a
        `CREATE INDEX` inside this migration would be dead weight on the parent with no
        partition to apply to yet."""
        assert "CREATE INDEX" not in FORWARD_SQL.upper()


# --------------------------------------------------------------------------- #
# memory_item.epoch_id
# --------------------------------------------------------------------------- #


class TestMemoryItemEpochColumn:
    def test_epoch_id_column_added(self) -> None:
        assert re.search(
            r"ALTER TABLE\s+memory_item\s+ADD COLUMN\s+epoch_id\s+integer\s*;",
            FORWARD_SQL,
            re.IGNORECASE,
        )

    def test_epoch_id_is_nullable(self) -> None:
        """Not NOT NULL: every existing `memory_item` row (and every row this repository's
        insert path writes today) predates any writer for this column — PLAN.md §11 M3 owns
        that writer, out of this chunk's file list. A NOT NULL column with no writer would
        make `insert_memory_item` fail on every call the moment this migration lands."""
        stmt = re.search(r"ALTER TABLE\s+memory_item\s+ADD COLUMN\s+epoch_id[^;]*;", FORWARD_SQL, re.IGNORECASE)
        assert stmt
        assert "NOT NULL" not in stmt.group(0).upper()
