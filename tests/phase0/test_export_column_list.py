"""tests/phase0/test_export_column_list.py -- export-and-quarantine-routes chunk.

Defect (1) from the BMAD evaluation (finding C3): `iter_export_rows` used `SELECT * FROM {table}`,
which streamed `memory_item.embedding` (`halfvec(768)`) and `.lexemes` (`tsvector`) through
`GET /export/project` for every row, and would silently pick up any future column a migration
added to any of the five exported tables -- nobody would have decided that column should leave
the repository.

The fix (`stores/pg/repo.py`'s `_EXPORT_COLUMNS` / `_EXPORT_EXCLUDED_COLUMNS`) replaces `SELECT *`
with an explicit column list per table. That needs TWO controls, not one, and the first version of
this file only had the second:

1. **The statement half.** `TestTheExportStatementItselfCarriesTheColumnList` drives the real
   `Repo.iter_export_rows` (and `ScopedRepo.iter_export_rows`, the second entry point into the
   same `_impl_iter_export_rows`) against a fake connection that records the SQL it is handed, and
   asserts the statement that actually reaches the database projects exactly `_EXPORT_COLUMNS[t]`.
   Asserting on the CONSTANT alone cannot fail for the reason this file exists: restoring the
   literal `SELECT *` to `_impl_iter_export_rows` while leaving `_EXPORT_COLUMNS` in place -- i.e.
   re-introducing the ORIGINAL defect verbatim -- left every constant-only assertion green.
2. **The schema half.** `TestExportColumnListMatchesRealSchema` parses the real DDL (every
   `CREATE TABLE` plus every column-shaped `ALTER TABLE` across the whole migration tree, so
   `memory_item.epoch_id` from 0004_lifecycle.sql counts) and asserts every real column of every
   exported table is accounted for by EXACTLY one of "in its export column list" or "in its
   documented excluded set". A migration that adds a column and forgets `repo.py` fails here the
   next time this suite runs, offline, no Postgres required.

The two halves meet in `test_the_emitted_projection_equals_the_real_ddl_minus_the_excluded_set`,
which is the end-to-end claim: what the database is asked for is exactly what the schema says the
table has, minus the columns someone wrote down a reason for withholding.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.repo import (
    _EXPORT_COLUMNS,
    _EXPORT_EXCLUDED_COLUMNS,
    _EXPORT_TABLES,
    Repo,
)

pytestmark = pytest.mark.phase0

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(uuid.UUID("11111111-1111-1111-1111-111111111111"))

_CONSTRAINT_KEYWORDS = frozenset({"PRIMARY", "CHECK", "UNIQUE", "FOREIGN", "CONSTRAINT"})


# --------------------------------------------------------------------------- #
# DDL parsing -- the schema half's evidence source.
# --------------------------------------------------------------------------- #


def _split_top_level(text: str) -> list[str]:
    """Split on commas at paren-depth 0 -- a `CHECK (x IN (a, b, c))` column definition has
    commas that are NOT column separators, exactly like `test_migrations.py::_table_block`
    has to walk parens rather than regex up to the first `)`."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def _column_paren_content(sql: str, table: str) -> str | None:
    """Text strictly between the balanced `( ... )` of `CREATE TABLE {table} ( ... )`, or
    `None` if this migration file does not create that table."""
    m = re.search(rf"CREATE TABLE\s+{re.escape(table)}\s*\(", sql, re.IGNORECASE)
    if not m:
        return None
    start = m.end() - 1
    depth = 0
    for i in range(start, len(sql)):
        if sql[i] == "(":
            depth += 1
        elif sql[i] == ")":
            depth -= 1
            if depth == 0:
                return sql[start + 1 : i]
    raise AssertionError(f"unbalanced parens in CREATE TABLE {table}")


def _create_table_columns(sql: str, table: str) -> set[str]:
    content = _column_paren_content(sql, table)
    if content is None:
        return set()
    columns: set[str] = set()
    for entry in _split_top_level(content):
        entry = entry.strip()
        if not entry:
            continue
        first_token = entry.split()[0]
        if first_token.upper() in _CONSTRAINT_KEYWORDS:
            continue
        columns.add(first_token.lower())
    return columns


def _alter_column_ops(sql: str, table: str) -> list[tuple[str, str, str]]:
    """`(kind, name, new_name)` for every column-shaped `ALTER TABLE {table}`, IN SOURCE ORDER.

    DROP and RENAME are handled, not only ADD, and that is not hypothetical hardening: the
    "does the export list name a column the table does not have" check below is worthless
    without them. A migration that DROPs an exported column leaves the export list naming a
    column Postgres no longer has -- `SELECT ... dropped_col ... FROM memory_item` is an
    `UndefinedColumn` error, i.e. `GET /export/project` 500s on its first row -- and an
    add-only parser still reports that column as "real", so nothing goes red until a human
    runs the route against a real database. Order matters because `ADD x` then `DROP x` and
    `DROP x` then `ADD x` describe different schemas.
    """
    pattern = re.compile(
        rf"ALTER TABLE\s+{re.escape(table)}\s+"
        r"(?:ADD COLUMN(?:\s+IF NOT EXISTS)?\s+(?P<added>\w+)"
        r"|DROP COLUMN(?:\s+IF EXISTS)?\s+(?P<dropped>\w+)"
        r"|RENAME COLUMN\s+(?P<renamed>\w+)\s+TO\s+(?P<renamed_to>\w+))",
        re.IGNORECASE,
    )
    ops: list[tuple[str, str, str]] = []
    for m in pattern.finditer(sql):
        if m.group("added"):
            ops.append(("add", m.group("added").lower(), ""))
        elif m.group("dropped"):
            ops.append(("drop", m.group("dropped").lower(), ""))
        else:
            ops.append(("rename", m.group("renamed").lower(), m.group("renamed_to").lower()))
    return ops


def _apply_alter_column_ops(columns: set[str], ops: list[tuple[str, str, str]]) -> set[str]:
    result = set(columns)
    for kind, name, new_name in ops:
        if kind == "add":
            result.add(name)
        elif kind == "drop":
            result.discard(name)
        else:
            result.discard(name)
            result.add(new_name)
    return result


def _real_columns(table: str) -> set[str]:
    """Every column `table` actually has, across the whole migration tree (never just one
    file) and in migration order -- `memory_item.epoch_id` only exists because
    0004_lifecycle.sql's `ALTER TABLE` is included here; reading only 0002_partitioned.sql
    would silently miss it."""
    columns: set[str] = set()
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if path.name.endswith(".rollback.sql"):
            continue
        sql = path.read_text(encoding="utf-8")
        columns |= _create_table_columns(sql, table)
        columns = _apply_alter_column_ops(columns, _alter_column_ops(sql, table))
    assert columns, f"no columns found for {table} -- migration glob or table name is wrong"
    return columns


def _declared_columns(table: str) -> set[str]:
    return {c.strip() for c in _EXPORT_COLUMNS[table].split(",")}


# --------------------------------------------------------------------------- #
# The fake database. Records the statements it is handed and returns no rows --
# the thing under test is WHICH SQL the export issues, which is exactly what a
# fake connection can prove and a constant cannot.
# --------------------------------------------------------------------------- #


class _FakeCursor:
    def __init__(self, log: list[tuple[str, Any]], *, name: str | None = None) -> None:
        self._log = log
        self.name = name
        self.itersize = 100

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return self

    def __iter__(self) -> Iterator[Any]:
        return iter(())

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeConnection:
    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self._log = log

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return _FakeCursor(self._log)

    def cursor(self, name: str | None = None, **kwargs: Any) -> _FakeCursor:
        return _FakeCursor(self._log, name=name)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConnection]:
        yield self


class _FakePool:
    def __init__(self) -> None:
        self.log: list[tuple[str, Any]] = []

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _FakeConnection(self.log)


def _drive_unscoped_export() -> list[tuple[str, Any]]:
    pool = _FakePool()
    repo = Repo(pool, FakeClock(EPOCH))  # type: ignore[arg-type]
    list(repo.iter_export_rows(PROJECT))
    return pool.log


def _drive_scoped_export() -> list[tuple[str, Any]]:
    """`ScopedRepo.iter_export_rows` is the OTHER caller of `_impl_iter_export_rows` (it runs
    inside a caller-owned `Repo.tx`), so a fix applied to only one of the two entry points
    would leave `/export/project`'s sibling path still shipping raw vectors."""
    pool = _FakePool()
    repo = Repo(pool, FakeClock(EPOCH))  # type: ignore[arg-type]
    with repo.tx(PROJECT) as tx:
        list(tx.iter_export_rows())
    return pool.log


_DRIVERS: dict[str, Callable[[], list[tuple[str, Any]]]] = {
    "Repo.iter_export_rows": _drive_unscoped_export,
    "ScopedRepo.iter_export_rows": _drive_scoped_export,
}

_SELECT_RE = re.compile(
    r"^\s*SELECT\s+(?P<columns>.+?)\s+FROM\s+(?P<table>\w+)\s+WHERE\b",
    re.IGNORECASE | re.DOTALL,
)


def _export_selects(log: list[tuple[str, Any]]) -> list[tuple[str, str, str]]:
    """`(sql, table, projection)` for every statement the export issued against an exported
    table. The GUC statement `scoped()` issues first is not a SELECT against one of these
    tables, so it never appears here."""
    found: list[tuple[str, str, str]] = []
    for sql, _params in log:
        m = _SELECT_RE.match(sql)
        if m and m.group("table") in _EXPORT_TABLES:
            found.append((sql, m.group("table"), m.group("columns").strip()))
    return found


# --------------------------------------------------------------------------- #
# 1. The statement half -- what actually reaches the database.
# --------------------------------------------------------------------------- #


class TestTheExportStatementItselfCarriesTheColumnList:
    """The control that would have caught the ORIGINAL defect. Every assertion here reads the
    SQL `_impl_iter_export_rows` issued, never a module constant: restoring `SELECT *` to that
    method is the exact original bug, and it must turn this class red on its own.
    """

    @pytest.mark.parametrize("driver", sorted(_DRIVERS))
    def test_no_export_statement_uses_select_star(self, driver: str) -> None:
        log = _DRIVERS[driver]()
        offenders = [sql for sql, _ in log if re.search(r"SELECT\s+\*", sql, re.IGNORECASE)]
        assert not offenders, f"{driver} issued SELECT *: {offenders}"

    @pytest.mark.parametrize("driver", sorted(_DRIVERS))
    def test_one_statement_per_exported_table_in_declaration_order(self, driver: str) -> None:
        selects = _export_selects(_DRIVERS[driver]())
        assert [table for _sql, table, _cols in selects] == list(_EXPORT_TABLES)

    @pytest.mark.parametrize("driver", sorted(_DRIVERS))
    def test_each_statement_projects_exactly_its_declared_column_list(self, driver: str) -> None:
        for _sql, table, projection in _export_selects(_DRIVERS[driver]()):
            assert projection == _EXPORT_COLUMNS[table], (
                f"{driver} projected {projection!r} for {table}, not the declared "
                f"_EXPORT_COLUMNS entry"
            )

    @pytest.mark.parametrize("driver", sorted(_DRIVERS))
    def test_the_memory_item_statement_never_names_embedding_or_lexemes(self, driver: str) -> None:
        """The defect this whole file exists to close, asserted against the SQL rather than
        against the constant that is supposed to feed it."""
        projections = [
            projection
            for _sql, table, projection in _export_selects(_DRIVERS[driver]())
            if table == "memory_item"
        ]
        assert projections, "the export issued no statement against memory_item"
        for projection in projections:
            # Tokenised, not a substring test: `embedding_model_id` and
            # `embedding_model_version` are ordinary scalar columns that legitimately CONTAIN
            # the word, and a substring assertion here would either fail on them or have to be
            # loosened into something that stops proving anything.
            emitted = {column.strip() for column in projection.split(",")}
            assert "embedding" not in emitted
            assert "lexemes" not in emitted

    @pytest.mark.parametrize("driver", sorted(_DRIVERS))
    def test_every_export_statement_still_carries_the_project_id_predicate(
        self, driver: str
    ) -> None:
        """Invariant 4 regression guard: narrowing the projection must not have touched the
        WHERE clause that keeps one project's export inside that project."""
        selects = _export_selects(_DRIVERS[driver]())
        assert selects
        for sql, _table, _cols in selects:
            assert "WHERE project_id = %(project_id)s" in sql

    @pytest.mark.parametrize("table", _EXPORT_TABLES)
    def test_the_emitted_projection_equals_the_real_ddl_minus_the_excluded_set(
        self, table: str
    ) -> None:
        """The two halves joined: the columns the database is actually asked for are exactly
        the columns the migration tree says the table has, minus the ones someone recorded a
        reason for withholding. Neither a `SELECT *` regression nor a schema drift can satisfy
        this one."""
        emitted = {
            column.strip()
            for _sql, emitted_table, projection in _export_selects(_drive_unscoped_export())
            if emitted_table == table
            for column in projection.split(",")
        }
        assert emitted == _real_columns(table) - _EXPORT_EXCLUDED_COLUMNS[table]


# --------------------------------------------------------------------------- #
# 2. The schema half -- what the migration tree says the tables have.
# --------------------------------------------------------------------------- #


class TestExportColumnListMatchesRealSchema:
    """Parses migrations/*.sql, never repo.py's own claims about itself."""

    @pytest.mark.parametrize("table", _EXPORT_TABLES)
    def test_every_real_column_is_exported_or_consciously_excluded(self, table: str) -> None:
        real = _real_columns(table)
        declared = _declared_columns(table)
        missing = real - (declared | _EXPORT_EXCLUDED_COLUMNS[table])
        assert not missing, (
            f"{table} has real column(s) {sorted(missing)} that are neither exported nor "
            f"excluded -- a migration added a column to {table} that no one decided should "
            f"(or should not) leave the repository via /export/project"
        )

    @pytest.mark.parametrize("table", _EXPORT_TABLES)
    def test_export_list_names_no_column_the_table_does_not_have(self, table: str) -> None:
        """The opposite drift: the hand-typed list naming a column that was renamed or
        dropped, which would 500 the export route instead of silently over-sharing."""
        phantom = _declared_columns(table) - _real_columns(table)
        assert not phantom, f"{table}'s export list names non-existent column(s) {sorted(phantom)}"

    @pytest.mark.parametrize("table", _EXPORT_TABLES)
    def test_excluded_columns_are_real_columns_of_that_table(self, table: str) -> None:
        """An excluded set that names a column the table does not have is a stale reason: it
        silently stops covering anything, and the completeness check above then has a hole
        nobody can see."""
        stale = _EXPORT_EXCLUDED_COLUMNS[table] - _real_columns(table)
        assert not stale, f"{table} excludes non-existent column(s) {sorted(stale)}"

    @pytest.mark.parametrize("table", _EXPORT_TABLES)
    def test_excluded_columns_are_disjoint_from_the_export_list(self, table: str) -> None:
        """A column cannot be simultaneously "exported" and "excluded" -- that would make
        the two sets' union meaningless as a completeness check."""
        assert not (_declared_columns(table) & _EXPORT_EXCLUDED_COLUMNS[table])

    def test_raw_embedding_and_lexemes_are_the_excluded_memory_item_columns(self) -> None:
        assert _EXPORT_EXCLUDED_COLUMNS["memory_item"] == {"embedding", "lexemes"}

    def test_all_three_export_constants_have_the_same_keys(self) -> None:
        assert set(_EXPORT_COLUMNS) == set(_EXPORT_TABLES)
        assert set(_EXPORT_EXCLUDED_COLUMNS) == set(_EXPORT_TABLES)


# --------------------------------------------------------------------------- #
# 3. The parser itself, proved against fabricated DDL rather than by mutating a
#    shipped migration file.
# --------------------------------------------------------------------------- #


class TestParserCatchesAnUnaccountedColumn:
    _FAKE_DDL = """
    CREATE TABLE widget (
        id uuid NOT NULL,
        project_id uuid NOT NULL,
        secret_field text,
        PRIMARY KEY (project_id, id)
    ) PARTITION BY LIST (project_id);
    """

    def _real(self, ddl: str) -> set[str]:
        return _apply_alter_column_ops(
            _create_table_columns(ddl, "widget"), _alter_column_ops(ddl, "widget")
        )

    def test_new_column_not_in_export_or_excluded_is_reported_missing(self) -> None:
        real = self._real(self._FAKE_DDL)
        assert real == {"id", "project_id", "secret_field"}
        assert real - ({"id", "project_id"} | set()) == {"secret_field"}

    def test_consciously_excluding_the_new_column_clears_the_check(self) -> None:
        real = self._real(self._FAKE_DDL)
        assert not (real - ({"id", "project_id"} | {"secret_field"}))

    def test_alter_table_add_column_is_picked_up(self) -> None:
        ddl = self._FAKE_DDL + "\nALTER TABLE widget ADD COLUMN epoch_id integer;\n"
        assert self._real(ddl) == {"id", "project_id", "secret_field", "epoch_id"}

    def test_alter_table_drop_column_removes_it_so_a_stale_export_entry_is_phantom(self) -> None:
        ddl = self._FAKE_DDL + "\nALTER TABLE widget DROP COLUMN secret_field;\n"
        real = self._real(ddl)
        assert real == {"id", "project_id"}
        assert {"id", "project_id", "secret_field"} - real == {"secret_field"}

    def test_alter_table_rename_column_moves_the_name(self) -> None:
        ddl = self._FAKE_DDL + "\nALTER TABLE widget RENAME COLUMN secret_field TO public_field;\n"
        assert self._real(ddl) == {"id", "project_id", "public_field"}

    def test_add_then_drop_and_drop_then_add_are_not_the_same_schema(self) -> None:
        """Source order is applied, not set union: an add-then-drop leaves the column gone and
        a drop-then-add leaves it present."""
        add_then_drop = self._FAKE_DDL + (
            "\nALTER TABLE widget ADD COLUMN tmp text;"
            "\nALTER TABLE widget DROP COLUMN tmp;\n"
        )
        drop_then_add = self._FAKE_DDL + (
            "\nALTER TABLE widget DROP COLUMN secret_field;"
            "\nALTER TABLE widget ADD COLUMN secret_field text;\n"
        )
        assert "tmp" not in self._real(add_then_drop)
        assert "secret_field" in self._real(drop_then_add)

    def test_if_not_exists_and_if_exists_forms_are_parsed(self) -> None:
        ddl = self._FAKE_DDL + (
            "\nALTER TABLE widget ADD COLUMN IF NOT EXISTS added_col text;"
            "\nALTER TABLE widget DROP COLUMN IF EXISTS secret_field;\n"
        )
        assert self._real(ddl) == {"id", "project_id", "added_col"}

    def test_non_column_alters_are_ignored(self) -> None:
        """`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` (0003_rls.sql issues one per table)
        must not be mistaken for a column operation."""
        ddl = self._FAKE_DDL + (
            "\nALTER TABLE widget ENABLE ROW LEVEL SECURITY;"
            "\nALTER TABLE widget FORCE ROW LEVEL SECURITY;\n"
        )
        assert self._real(ddl) == {"id", "project_id", "secret_field"}
