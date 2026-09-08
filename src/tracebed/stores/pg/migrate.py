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
already solved"). This module fixes the migrations directory and provides the
only supported mutating surface: one pinned-yoyo, one-backend atomic unit per
migration.  It deliberately does not expose yoyo's native split apply or
rollback path through a subprocess call.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from shlex import split as shell_split
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from yoyo import get_backend, read_migrations
from yoyo.migrations import MigrationList

from tracebed.stores.pg.authority_dsn import parse_authority_migration_url

_PINNED_YOYO_VERSION = "9.0.0"

# Source-checkout fallback.  Wheels include this directory at
# ``tracebed/_migrations`` via Hatch's ``force-include`` configuration.  Keep
# this public constant for callers that deliberately inspect a source tree;
# migration execution itself must use ``migration_directory()`` below.
MIGRATIONS_DIR = Path(__file__).resolve().parents[4] / "migrations"
_PACKAGE_MIGRATIONS_DIR = "_migrations"

__all__ = [
    "MIGRATIONS_DIR",
    "apply_migrations",
    "current_revision",
    "migration_directory",
    "read_all_migrations",
    "rollback_migrations",
]


def _is_migration_directory(path: Path) -> bool:
    """Whether ``path`` has the minimum complete yoyo migration shape."""
    return path.is_dir() and (path / "yoyo.ini").is_file() and any(path.glob("*.sql"))


@contextmanager
def migration_directory() -> Iterator[Path]:
    """Yield migrations packaged with Tracebed, then fall back to source.

    ``importlib.resources.as_file`` makes this work even when an importer does
    not expose a real filesystem path (for example, a zip-backed installation).
    The package resource is always preferred: an installed wheel must execute
    the SQL it shipped, not accidentally discover an unrelated working
    directory.  The source fallback preserves editable-checkout development.
    """
    try:
        packaged = resources.files("tracebed").joinpath(_PACKAGE_MIGRATIONS_DIR)
    except (ModuleNotFoundError, TypeError):  # pragma: no cover - broken import machinery
        packaged = None

    if packaged is not None and packaged.is_dir():
        with resources.as_file(packaged) as resolved:
            if _is_migration_directory(resolved):
                yield resolved
                return

    if _is_migration_directory(MIGRATIONS_DIR):
        yield MIGRATIONS_DIR
        return

    raise FileNotFoundError(
        "Tracebed migrations were not found in packaged tracebed/_migrations "
        f"or source fallback {MIGRATIONS_DIR}"
    )


def read_all_migrations() -> MigrationList:
    """Load packaged migrations, refusing to treat "not found" as "nothing to do".

    `yoyo.read_migrations` returns an empty list for a directory that does not
    exist.  Without the package-resource lookup and explicit guard, an
    installed (non-editable) wheel could report success while applying no
    schema at all.
    """
    with migration_directory() as directory:
        migrations = read_migrations(str(directory))
        if not migrations:
            raise FileNotFoundError(
                "no migrations found in the selected Tracebed migration directory"
            )
        # yoyo defers opening each forward and ``.rollback.sql`` file until
        # ``Migration.load()``.  A package resource extracted by ``as_file``
        # may disappear as soon as this context exits (notably for a wheel on
        # ``sys.path``), so materialize every migration while its resource
        # context is still alive.  Loaded yoyo steps retain their SQL strings,
        # allowing apply, rollback, and revision inspection to operate after
        # this function returns without depending on a vanished temp path.
        for migration in migrations:
            migration.load()
    return migrations


_PSYCOPG3_SCHEME = "postgresql+psycopg://"

_MIGRATION_ATOMIC_RUNNER_GUC = "tracebed.atomic_migration_runner"
_MIGRATION_TRUSTED_OPTIONS = (
    "-c tracebed.cluster_scope=dedicated "
    "-c tracebed.ingress_quarantined=on "
    f"-c {_MIGRATION_ATOMIC_RUNNER_GUC}=on "
    "-c search_path=public,pg_catalog"
)


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
    try:
        original_dsn, original = parse_authority_migration_url(dsn)
    except ValueError as exc:
        raise ValueError("Tracebed migration runner requires a PostgreSQL URL DSN") from exc
    if original.scheme == "postgresql":
        dsn = _PSYCOPG3_SCHEME + original_dsn[len("postgresql://") :]
    else:
        dsn = _PSYCOPG3_SCHEME + original_dsn[len("postgres://") :]

    # Yoyo opens a separate owner connection for its bookkeeping tables. Do
    # not preserve arbitrary caller ``options``: an owner-controlled option
    # could replace search_path or the invocation receipt. The only accepted
    # source options are the exact external dedicated/ingress attestations;
    # they are re-composed in one trusted fixed value with the atomic-wrapper
    # guard and catalog-first search path.
    parsed = urlsplit(dsn)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    option_values = [value for key, value in query if key == "options"]
    query = [(key, value) for key, value in query if key != "options"]
    attestation_tokens: set[str] = set()
    for option_value in option_values:
        try:
            tokens = shell_split(option_value)
        except ValueError:
            # A malformed caller option is never forwarded to libpq's owner
            # migration connection.
            continue
        for index in range(0, len(tokens) - 1):
            if tokens[index] == "-c" and tokens[index + 1] in {
                "tracebed.cluster_scope=dedicated",
                "tracebed.ingress_quarantined=on",
            }:
                attestation_tokens.add(tokens[index + 1])
    if attestation_tokens != {
        "tracebed.cluster_scope=dedicated",
        "tracebed.ingress_quarantined=on",
    }:
        # The authority SQL will independently fail before locks as well;
        # this keeps a caller from smuggling unrelated libpq flags while
        # still letting ordinary pre-0011 development migrations run through
        # the same trusted wrapper.
        trusted_options = (
            f"-c {_MIGRATION_ATOMIC_RUNNER_GUC}=on -c search_path=public,pg_catalog"
        )
    else:
        trusted_options = _MIGRATION_TRUSTED_OPTIONS
    query.append(("options", trusted_options))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query, quote_via=quote), parsed.fragment)
    )


def apply_migrations(
    dsn: str, *, through: str | None = None, include_deployment: bool = False
) -> list[str]:
    """Apply every pending migration in `migrations/`, in dependency order.

    Returns the ids applied (empty if the schema was already current — this
    makes the function safe to call at process start-up unconditionally).
    ``through`` is the exact packaged migration id for release-generation
    reference builds that must stop before a later transition.

    The pending set is computed INSIDE `backend.lock()`. Computing it outside
    lets two processes booting together both observe the same pending set;
    the second would then re-run migrations the first already applied and
    fail on `relation ... already exists` — or, worse, partially re-run one.
    """
    backend = get_backend(_yoyo_dsn(dsn))
    migrations = read_all_migrations()
    canonical_migrations = {migration.id: migration for migration in migrations}
    canonical_dependencies = _canonical_dependency_map(canonical_migrations)
    if through is not None and through not in canonical_migrations:
        raise ValueError(f"unknown Tracebed migration target: {through}")
    with backend.lock():
        backend.ensure_internal_schema_updated()
        to_apply = backend.to_apply(migrations)
        if through is None:
            # `0013_erasure_deployment` deliberately is not a normal schema
            # bootstrap step: its preflight authenticates a closed, active
            # c12 deployment and its LOGIN publication is controller-owned.
            # Existing callers keep their c12 boundary unless they opt into
            # the explicit E4 target below.
            targets = (
                list(to_apply)
                if include_deployment
                else [migration for migration in to_apply if migration.id != "0013_erasure_deployment"]
            )
        else:
            # ``through`` is a graph target, not a promise that it is
            # pending.  If it was already applied, do not accidentally apply
            # every later pending migration merely because it is absent from
            # ``to_apply``.
            allowed_ids: set[str] = set()
            for migration in migrations:
                allowed_ids.add(migration.id)
                if migration.id == through:
                    break
            targets = [migration for migration in to_apply if migration.id in allowed_ids]
        ids = [migration.id for migration in targets]
        for migration in targets:
            _apply_migration_atomically(
                backend, migration, canonical_migrations, canonical_dependencies
            )
    return ids


def _atomic_apply_after_sql_barrier(_backend: Any, _migration: Any) -> None:
    """Narrow failure-injection seam after forward SQL, before the yoyo log."""


def _atomic_apply_after_log_barrier(_backend: Any, _migration: Any) -> None:
    """Narrow failure-injection seam after the yoyo log, before marking applied."""


def _atomic_apply_log_migration(backend: Any, migration: Any) -> None:
    """Insert yoyo's normal apply audit record in the enclosing transaction."""

    backend.log_migration(migration, "apply")


def _atomic_apply_mark_migration(backend: Any, migration: Any) -> None:
    """Mark an applied migration without yoyo's separate default transaction."""

    backend.mark_one(migration, log=False)


def _atomic_rollback_after_sql_barrier(_backend: Any, _migration: Any) -> None:
    """Narrow failure-injection seam after rollback SQL, before the yoyo log."""


def _atomic_rollback_after_log_barrier(_backend: Any, _migration: Any) -> None:
    """Narrow failure-injection seam after the yoyo log, before unmarking."""


def _atomic_rollback_log_migration(backend: Any, migration: Any) -> None:
    """Insert yoyo's normal rollback audit record in the enclosing transaction."""

    backend.log_migration(migration, "rollback")


def _atomic_rollback_unmark_migration(backend: Any, migration: Any) -> None:
    """Delete yoyo's applied marker without its separate default transaction."""

    backend.unmark_one(migration, log=False)


def _migration_dependency_ids(migration: Any) -> tuple[str, ...]:
    """Return a stable dependency-id tuple, refusing malformed yoyo objects."""

    dependencies = getattr(migration, "depends", ())
    if dependencies is None:
        raise RuntimeError("Tracebed atomic migration target has an invalid dependency map")
    dependency_ids: list[str] = []
    for dependency in dependencies:
        dependency_id = getattr(dependency, "id", None)
        if not isinstance(dependency_id, str):
            raise RuntimeError("Tracebed atomic migration target has an invalid dependency map")
        dependency_ids.append(dependency_id)
    return tuple(sorted(dependency_ids))


def _canonical_dependency_map(canonical_migrations: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Authenticate that yoyo's dependency objects are this package's objects."""

    dependency_map: dict[str, tuple[str, ...]] = {}
    for migration_id, migration in canonical_migrations.items():
        dependency_ids = _migration_dependency_ids(migration)
        if any(canonical_migrations.get(dependency_id) is None for dependency_id in dependency_ids):
            raise RuntimeError("Tracebed atomic migration target has an invalid dependency map")
        dependency_map[migration_id] = dependency_ids
    return dependency_map


def _require_atomic_migration_contract(
    backend: Any,
    migration: Any,
    canonical_migrations: dict[str, Any],
    canonical_dependencies: dict[str, tuple[str, ...]],
    *,
    direction: str,
) -> None:
    """Fail closed unless the pinned yoyo-9 transactional contract is present.

    yoyo 9's native apply and rollback paths run migration SQL on copied
    backends, then log and mark/unmark in later transactions. Tracebed must
    instead use one owner connection and one outer yoyo transaction for both
    directions. This compatibility gate makes that narrow dependency on yoyo
    9.0.0 explicit.
    """

    try:
        installed_version = version("yoyo-migrations")
    except PackageNotFoundError as exc:  # pragma: no cover - runtime packaging failure
        raise RuntimeError("Tracebed atomic migration requires yoyo-migrations 9.0.0") from exc
    if installed_version != _PINNED_YOYO_VERSION:
        raise RuntimeError("Tracebed atomic migration requires yoyo-migrations 9.0.0")
    if direction not in {"apply", "rollback"}:
        raise RuntimeError("Tracebed atomic migration direction is invalid")
    migration_id = getattr(migration, "id", None)
    migration_hash = getattr(migration, "hash", None)
    if not isinstance(migration_id, str) or not isinstance(migration_hash, str):
        raise RuntimeError("Tracebed atomic migration target is not a packaged migration object")
    canonical = canonical_migrations.get(migration_id)
    if (
        canonical is not migration
        or getattr(canonical, "hash", None) != migration_hash
    ):
        raise RuntimeError("Tracebed atomic migration target is not a packaged migration object")
    if canonical_dependencies.get(migration_id) != _migration_dependency_ids(migration):
        raise RuntimeError("Tracebed atomic migration target has an invalid dependency map")
    load_migration = getattr(migration, "load", None)
    if not callable(load_migration):
        raise RuntimeError("Tracebed atomic migration yoyo-9 contract is unavailable")
    load_migration()
    if getattr(migration, "use_transactions", None) is not True:
        raise RuntimeError("Tracebed atomic migration requires transactional migrations")
    if getattr(backend, "has_transactional_ddl", None) is not True:
        raise RuntimeError("Tracebed atomic migration requires transactional DDL")
    state_method = "mark_one" if direction == "apply" else "unmark_one"
    if not all(
        callable(getattr(backend, name, None))
        for name in ("transaction", "log_migration", state_method)
    ) or not callable(getattr(migration, "process_steps", None)):
        raise RuntimeError("Tracebed atomic migration yoyo-9 contract is unavailable")


def _run_migration_atomically(
    backend: Any,
    migration: Any,
    canonical_migrations: dict[str, Any],
    canonical_dependencies: dict[str, tuple[str, ...]],
    *,
    direction: str,
) -> None:
    """Run one packaged yoyo transition, log it, and update its marker atomically.

    ``migration.process_steps`` opens a savepoint because the yoyo backend is
    already in this outer transaction.  Therefore any error at the SQL/log/
    mark boundary rolls back every observable part of an apply or rollback,
    including transactional DDL and catalog role changes.
    """

    _require_atomic_migration_contract(
        backend,
        migration,
        canonical_migrations,
        canonical_dependencies,
        direction=direction,
    )
    with backend.transaction():
        migration.process_steps(backend, direction)
        if direction == "apply":
            _atomic_apply_after_sql_barrier(backend, migration)
            _atomic_apply_log_migration(backend, migration)
            _atomic_apply_after_log_barrier(backend, migration)
            _atomic_apply_mark_migration(backend, migration)
        else:
            _atomic_rollback_after_sql_barrier(backend, migration)
            _atomic_rollback_log_migration(backend, migration)
            _atomic_rollback_after_log_barrier(backend, migration)
            _atomic_rollback_unmark_migration(backend, migration)


def _apply_migration_atomically(
    backend: Any,
    migration: Any,
    canonical_migrations: dict[str, Any],
    canonical_dependencies: dict[str, tuple[str, ...]],
) -> None:
    """Apply one packaged migration as one SQL/log/mark transaction."""

    _run_migration_atomically(
        backend,
        migration,
        canonical_migrations,
        canonical_dependencies,
        direction="apply",
    )


def _rollback_migration_atomically(
    backend: Any,
    migration: Any,
    canonical_migrations: dict[str, Any],
    canonical_dependencies: dict[str, tuple[str, ...]] | None = None,
) -> None:
    """Rollback one packaged migration as one SQL/log/unmark transaction."""

    if canonical_dependencies is None:
        canonical_dependencies = _canonical_dependency_map(canonical_migrations)
    _run_migration_atomically(
        backend,
        migration,
        canonical_migrations,
        canonical_dependencies,
        direction="rollback",
    )


def rollback_migrations(dsn: str, *, all: bool = False) -> list[str]:
    """Roll back the most recently applied migration.

    Pass `all=True` to roll back every applied migration instead — this is
    what PHASE-0 Task 5's proving test (wrapper apply then wrapper rollback
    clean) exercises via `rollback_migrations(dsn, all=True)`. Returns the
    ids rolled back, most-recently-applied first.

    Each migration's rollback comes from its `<name>.rollback.sql` companion.
    yoyo 9's native rollback splits migration SQL, audit logging, and unmarking
    across transactions. Tracebed replaces both native mutation paths with a
    version-pinned one-connection outer transaction, so a crash or failure
    cannot leave DDL committed while `_yoyo_migration` still claims 0011 is
    applied. Each target is its own atomic unit for ``all=True``.
    """
    backend = get_backend(_yoyo_dsn(dsn))
    migrations = read_all_migrations()
    canonical_migrations = {migration.id: migration for migration in migrations}
    canonical_dependencies = _canonical_dependency_map(canonical_migrations)
    with backend.lock():
        backend.ensure_internal_schema_updated()
        applied = backend.to_rollback(migrations)
        targets = applied if all else applied[:1]
        ids = [m.id for m in targets]
        for migration in targets:
            _rollback_migration_atomically(
                backend, migration, canonical_migrations, canonical_dependencies
            )
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
    migrations run as the owner role, never the app role; deployment identity setup belongs to
    the owner bootstrap / Compose ``db-bootstrap`` one-shot.
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
