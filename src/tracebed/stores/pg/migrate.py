"""Thin yoyo runner (PHASE-0 Task 5/6; contract §1, §5, DECISIONS D-034).

CI, the Phase 0 gate (`harness/phase0_gate.py`), and
`tests/phase0/test_migrations.py` call `apply_migrations` /
`rollback_migrations` / `current_revision` instead of shelling out to the
`yoyo` CLI, so the migration tree that gates the build is exercised through
the exact same code path in every environment. This module lives under
`stores/pg/` — the one package `scripts/raw_sql_lint.py` permits to execute
SQL — because `yoyo` issues SQL directly against its own migration-tracking
table (`_yoyo_migration`, managed entirely by yoyo, not by us).

Migrations themselves are plain SQL (D-034: "Alembic drags SQLAlchemy against
the lean-deps rule; a first-party runner reinvents ordering/locking yoyo
already solved"). This module adds nothing to what yoyo does; it only fixes
the migrations directory and gives Tracebed's own tests and tooling one
importable surface instead of a subprocess call.
"""

from __future__ import annotations

from pathlib import Path

from yoyo import get_backend, read_migrations
from yoyo.migrations import MigrationList

# src/tracebed/stores/pg/migrate.py -> repo root is four `.parent`s up.
MIGRATIONS_DIR = Path(__file__).resolve().parents[4] / "migrations"

__all__ = [
    "MIGRATIONS_DIR",
    "apply_migrations",
    "current_revision",
    "read_all_migrations",
    "rollback_migrations",
]


def read_all_migrations() -> MigrationList:
    """Load `migrations/`, refusing to treat "not found" as "nothing to do".

    `yoyo.read_migrations` returns an empty list for a directory that does
    not exist. Without this guard, running from an installed (non-editable)
    package — where `parents[4]` is site-packages, not the repo root — would
    make `apply_migrations` return `[]` and report success against a database
    that has no schema at all. A migration runner that silently applies
    nothing is the worst possible failure mode for a security schema whose
    RLS policies are the isolation backstop.
    """
    if not MIGRATIONS_DIR.is_dir():
        raise FileNotFoundError(
            f"migrations directory not found at {MIGRATIONS_DIR}; "
            "tracebed must be installed from a source checkout (pip install -e .)"
        )
    migrations = read_migrations(str(MIGRATIONS_DIR))
    if not migrations:
        raise FileNotFoundError(f"no migrations found in {MIGRATIONS_DIR}")
    return migrations


_PSYCOPG3_SCHEME = "postgresql+psycopg://"

_PLAIN_SCHEMES = ("postgresql://", "postgres://")


def _yoyo_dsn(dsn: str) -> str:
    """Translate a standard Postgres DSN to yoyo's psycopg3 backend scheme.

    yoyo resolves its backend from the URI scheme, and it maps bare
    `postgresql://` to a backend that imports **psycopg2**. Tracebed ships
    **psycopg 3** (D-036: psycopg 3 is the mandated driver, and it is the one
    entry the licence policy admits under its conditional LGPL tier). psycopg2
    is therefore not installed and must not be — adding it would mean a second
    LGPL dependency carried solely to run migrations.

    Without this translation `get_backend()` raises
    `ModuleNotFoundError: No module named 'psycopg2'`, which meant migrations
    could never be applied on any machine and every integration test skipped
    with a message that read like "no database available". CI found it on the
    first run against a real Postgres; no amount of offline testing could have.

    Callers keep using ordinary `postgresql://` DSNs — the same string the
    application, psql and the compose file use. The scheme rewrite is local to
    yoyo and never leaves this module.
    """
    for scheme in _PLAIN_SCHEMES:
        if dsn.startswith(scheme):
            return _PSYCOPG3_SCHEME + dsn[len(scheme) :]
    return dsn


def apply_migrations(dsn: str) -> list[str]:
    """Apply every pending migration in `migrations/`, in dependency order.

    Returns the ids applied (empty if the schema was already current — this
    makes the function safe to call at process start-up unconditionally).

    The pending set is computed INSIDE `backend.lock()`. Computing it outside
    lets two processes booting together both observe the same pending set;
    the second would then re-run migrations the first already applied and
    fail on `relation ... already exists` — or, worse, partially re-run one.
    """
    backend = get_backend(_yoyo_dsn(dsn))
    migrations = read_all_migrations()
    with backend.lock():
        to_apply = backend.to_apply(migrations)
        ids = [m.id for m in to_apply]
        backend.apply_migrations(to_apply)
    return ids


def rollback_migrations(dsn: str, *, all: bool = False) -> list[str]:
    """Roll back the most recently applied migration.

    Pass `all=True` to roll back every applied migration instead — this is
    what PHASE-0 Task 5's proving test ("`yoyo apply` then `yoyo rollback`
    clean") exercises via `rollback_migrations(dsn, all=True)`. Returns the
    ids rolled back, most-recently-applied first.

    Each migration's rollback comes from its `<name>.rollback.sql` companion.
    yoyo treats a missing companion as "this step has no rollback" and
    silently un-marks the migration anyway, so those files are not optional
    decoration: without them this function would report a clean rollback over
    a database whose every table still exists.
    """
    backend = get_backend(_yoyo_dsn(dsn))
    migrations = read_all_migrations()
    with backend.lock():
        applied = backend.to_rollback(migrations)
        targets = applied if all else applied[:1]
        ids = [m.id for m in targets]
        backend.rollback_migrations(targets)
    return ids


def current_revision(dsn: str) -> list[str]:
    """Ids of every migration currently applied to `dsn`.

    Read-only — the programmatic equivalent of `yoyo list`. Ordered
    most-recently-applied first (yoyo's `to_rollback` reverses topological
    order); callers that care about set membership should compare sets. An
    empty list means either a fresh database or one that has been fully
    rolled back.
    """
    backend = get_backend(_yoyo_dsn(dsn))
    migrations = read_all_migrations()
    return [m.id for m in backend.to_rollback(migrations)]


def _main(argv: list[str] | None = None) -> int:
    """`python -m tracebed.stores.pg.migrate <apply|rollback|rollback-all|list>`.

    A thin CLI over the functions above, so the documented runbook command is REAL rather than a
    module import that silently does nothing (this module previously had no `__main__`, so
    `python -m ... apply` imported and exited 0 without touching the database). The DSN comes from
    `--dsn` or `$TB_STORAGE__PG_DSN` — the same variable the application and compose use — and
    migrations run as the owner role, never the app role (`docker/initdb/01-roles.sql`).
    """
    import argparse
    import os

    parser = argparse.ArgumentParser(
        prog="python -m tracebed.stores.pg.migrate",
        description="Apply, roll back, or list Tracebed's Postgres migrations.",
    )
    parser.add_argument("command", choices=("apply", "rollback", "rollback-all", "list"))
    parser.add_argument(
        "--dsn",
        default=os.environ.get("TB_STORAGE__PG_DSN"),
        help="Postgres DSN (default: $TB_STORAGE__PG_DSN)",
    )
    args = parser.parse_args(argv)
    dsn: str | None = args.dsn
    if not dsn:
        parser.error("no DSN: pass --dsn or set TB_STORAGE__PG_DSN")

    if args.command == "apply":
        applied = apply_migrations(dsn)
        print("applied: " + ", ".join(applied) if applied else "already current")
    elif args.command == "rollback":
        print("rolled back: " + ", ".join(rollback_migrations(dsn)))
    elif args.command == "rollback-all":
        print("rolled back: " + ", ".join(rollback_migrations(dsn, all=True)))
    else:  # list
        for migration_id in current_revision(dsn):
            print(migration_id)
    return 0


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(_main())
