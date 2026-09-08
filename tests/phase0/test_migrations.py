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
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest

pytestmark = pytest.mark.phase0

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

MIGRATION_IDS = (
    "0001_registries",
    "0002_partitioned",
    "0003_rls",
    "0004_lifecycle",
    "0005_bm25",
    "0006_q_update_ledger",
    "0007_project_provisioning",
    "0008_trace_learning_job",
    "0009_trace_index_terminal_freeze",
    "0010_authority_foundation",
    "0011_authority_cutover",
    "0012_erasure_saga",
    "0013_erasure_deployment",
)

# E4 is deliberately controller-applied from closed c12; ordinary migration
# bootstrap stops at the accepted c12 boundary.
BOOTSTRAP_MIGRATION_IDS = MIGRATION_IDS[:-1]

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


def test_yoyo_connection_rejects_caller_options_before_backend_selection() -> None:
    """The wrapper never forwards or normalizes caller option/search-path smuggling."""

    from tracebed.stores.pg.migrate import _yoyo_dsn

    with pytest.raises(ValueError, match="PostgreSQL URL DSN"):
        _yoyo_dsn(
            "postgresql://owner:secret@db.example/tracebed?"
            "options=-c%20tracebed.cluster_scope%3Ddedicated%20-c%20search_path%3Dhostile%2Cpublic"
        )


def test_yoyo_connection_recomposes_exact_authority_receipts_with_atomic_guard() -> None:
    """Bootstrap receipts preserve an ordinary transport URL through yoyo rewrite."""

    from psycopg.conninfo import conninfo_to_dict

    from tracebed.stores.pg import bootstrap
    from tracebed.stores.pg.migrate import _yoyo_dsn

    bootstrap_dsn = bootstrap._dedicated_cluster_dsn(
        "postgresql://owner:secret@db.example:5432/tracebed?sslmode=require",
        "dedicated",
        ingress_quarantined=True,
    )
    dsn = _yoyo_dsn(bootstrap_dsn)
    parsed = urlsplit(dsn)
    options = [value for key, value in parse_qsl(parsed.query) if key == "options"]
    assert options == [
        "-c tracebed.cluster_scope=dedicated -c tracebed.ingress_quarantined=on "
        "-c tracebed.atomic_migration_runner=on -c search_path=public,pg_catalog"
    ]
    assert dict(parse_qsl(parsed.query))["sslmode"] == "require"
    # yoyo's backend selector requires ``postgresql+psycopg``. Changing it
    # back for libpq parsing proves that its URL authority/path and preserved
    # transport query resolve exactly the same endpoint and identity.
    yoyo_libpq_view = "postgresql://" + dsn.removeprefix("postgresql+psycopg://")
    bootstrap_view = conninfo_to_dict(bootstrap_dsn)
    yoyo_view = conninfo_to_dict(yoyo_libpq_view)
    assert {key: bootstrap_view.get(key) for key in ("user", "password", "host", "port", "dbname")} == {
        key: yoyo_view.get(key) for key in ("user", "password", "host", "port", "dbname")
    }
    assert bootstrap_view.get("sslmode") == yoyo_view.get("sslmode") == "require"


@pytest.mark.parametrize(
    "dsn",
    (
        "postgresql://owner:secret@db.example:5432/tracebed?sslmode=require",
        "postgresql://owner:secret@127.0.0.1:5432/tracebed",
        "postgresql://owner%2Dname:sec%2Dret@db.example:5432/tracebed?sslmode=require",
        "postgresql://owner:secret@[::1]:5432/tracebed?sslmode=require",
    ),
    ids=("hostname-ssl", "ipv4", "escaped-user-password", "ipv6"),
)
def test_authority_url_coordinates_are_identical_for_psycopg_and_yoyo(dsn: str) -> None:
    """The shared fence admits only URL coordinates both clients resolve identically."""

    from psycopg.conninfo import conninfo_to_dict
    from yoyo.connections import parse_uri

    from tracebed.stores.pg.authority_dsn import authority_migration_coordinates

    expected = authority_migration_coordinates(dsn)
    libpq = conninfo_to_dict(dsn)
    yoyo = parse_uri("postgresql+psycopg://" + dsn.removeprefix("postgresql://"))
    libpq_coordinates = (
        libpq.get("user"),
        libpq.get("password"),
        libpq.get("host"),
        int(libpq["port"]) if libpq.get("port") else None,
        libpq.get("dbname"),
    )
    yoyo_coordinates = (yoyo.username, yoyo.password, yoyo.hostname, yoyo.port, yoyo.database)

    assert expected == libpq_coordinates == yoyo_coordinates


def test_migration_runner_rejects_keyword_conninfo_before_backend_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The URI-only yoyo backend contract fails before it can open a connection."""

    from tracebed.stores.pg import migrate

    def unexpected_backend(_dsn: str) -> object:
        raise AssertionError("keyword conninfo reached yoyo backend selection")

    monkeypatch.setattr(migrate, "get_backend", unexpected_backend)
    with pytest.raises(ValueError, match="PostgreSQL URL DSN"):
        migrate.apply_migrations("dbname=owner user=tracebed_owner host=localhost")


@pytest.mark.parametrize(
    "dsn",
    (
        "postgresql://owner:secret@db.example:5432/tracebed?user=shadow",
        "postgresql://owner:secret@db.example:5432/tracebed?PASSWORD=shadow",
        "postgresql://owner:secret@db.example:5432/tracebed?host=shadow",
        "postgresql://owner:secret@db.example:5432/tracebed?hostaddr=127.0.0.2",
        "postgresql://owner:secret@db.example:5432/tracebed?port=6432",
        "postgresql://owner:secret@db.example:5432/tracebed?dbname=shadow",
        "postgresql://owner:secret@db.example:5432/tracebed?database=shadow",
        "postgresql://owner:secret@db.example:5432/tracebed?service=shadow",
        "postgresql://owner:secret@db.example:5432/tracebed?servicefile=/tmp/rogue",
        "postgresql://owner:secret@db.example:5432/tracebed?passfile=/tmp/rogue",
        "postgresql://owner:secret@db.example:5432/tracebed?%75ser=shadow",
        "postgresql://owner:secret@db.example:5432/tracebed?sslmode=require&SSLMODE=disable",
        "postgresql://owner:secret@db.example:5432/tracebed?options=-c%20search_path%3Drogue",
        "postgresql://owner:secret@primary,standby:5432/tracebed",
        "postgresql://owner:secret@primary%2Cstandby:5432/tracebed",
        "postgresql://owner:secret@primary%2cstandby:5432/tracebed",
        "postgresql://owner:secret@primary%252Cstandby:5432/tracebed",
        "postgresql://owner:secret@db%2Eexample:5432/tracebed",
        "postgresql://owner:secret@db.example:5432/trace,bed",
        "postgresql://owner:secret@db.example:5432/trace%2Fbed",
        "postgresql://owner:secret@db.example:5432/trace%252Fbed",
        "postgresql://owner:secret@db.example:/tracebed",
        "postgresql://owner@shadow@db.example:5432/tracebed",
    ),
    ids=(
        "query-user",
        "query-password-case",
        "query-host",
        "query-hostaddr",
        "query-port",
        "query-dbname",
        "query-database",
        "query-service",
        "query-servicefile",
        "query-passfile",
        "query-percent-user",
        "query-duplicate-transport-key",
        "query-options",
        "raw-multi-host",
        "encoded-multi-host-uppercase",
        "encoded-multi-host-lowercase",
        "double-encoded-multi-host",
        "encoded-host-dot",
        "raw-database-comma",
        "encoded-database-separator",
        "double-encoded-database-separator",
        "empty-port",
        "ambiguous-user",
    ),
)
@pytest.mark.parametrize("operation", ("apply", "rollback"))
def test_migration_runner_rejects_ambiguous_url_before_backend_access(
    monkeypatch: pytest.MonkeyPatch, dsn: str, operation: str
) -> None:
    """Neither supported mutation direction may resolve conflicting URL coordinates."""

    from tracebed.stores.pg import migrate

    def unexpected_backend(_dsn: str) -> object:
        raise AssertionError("ambiguous URL reached yoyo backend selection")

    monkeypatch.setattr(migrate, "get_backend", unexpected_backend)
    runner = migrate.apply_migrations if operation == "apply" else migrate.rollback_migrations
    with pytest.raises(ValueError, match="PostgreSQL URL DSN"):
        runner(dsn)


def test_tracebed_apply_uses_one_backend_transaction_not_yoyo_native_copy_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supported API never delegates an apply to yoyo's split path."""

    from tracebed.stores.pg import migrate

    class FakeMigration:
        use_transactions = True

        def __init__(self, migration_id: str, migration_hash: str, depends: set[object]) -> None:
            self.id = migration_id
            self.hash = migration_hash
            self.depends = depends

        def load(self) -> None:
            return None

        def process_steps(self, backend: object, direction: str) -> None:
            assert backend is fake_backend
            assert direction == "apply"
            fake_backend.events.append(f"apply-sql:{self.id}")

    class FakeBackend:
        has_transactional_ddl = True

        def __init__(self) -> None:
            self.events: list[str] = []

        @contextmanager
        def lock(self) -> Iterator[None]:
            self.events.append("lock")
            yield

        @contextmanager
        def transaction(self) -> Iterator[None]:
            self.events.append("begin")
            try:
                yield
            except BaseException:
                self.events.append("rollback")
                raise
            else:
                self.events.append("commit")

        def ensure_internal_schema_updated(self) -> None:
            self.events.append("ensure")

        def to_apply(self, _migrations: object) -> list[FakeMigration]:
            self.events.append("select-target")
            return [first, second]

        def log_migration(self, received: FakeMigration, operation: str) -> None:
            assert operation == "apply"
            self.events.append(f"log:{received.id}")

        def mark_one(self, received: FakeMigration, *, log: bool) -> None:
            assert log is False
            self.events.append(f"mark:{received.id}")

        def apply_migrations(self, _targets: object) -> None:
            raise AssertionError("native yoyo apply path must not be called")

        def apply_one(self, _target: object) -> None:
            raise AssertionError("native yoyo apply-one path must not be called")

        def copy(self) -> object:
            raise AssertionError("atomic apply must not open yoyo's copied backend")

    first = FakeMigration("0001_registries", "first-hash", set())
    second = FakeMigration("0002_partitioned", "second-hash", {first})
    fake_backend = FakeBackend()
    monkeypatch.setattr(migrate, "get_backend", lambda _dsn: fake_backend)
    monkeypatch.setattr(migrate, "read_all_migrations", lambda: [first, second])
    monkeypatch.setattr(migrate, "version", lambda _distribution: "9.0.0")

    assert migrate.apply_migrations("postgresql://owner@db.example/tracebed") == [
        "0001_registries",
        "0002_partitioned",
    ]
    assert fake_backend.events == [
        "lock",
        "ensure",
        "select-target",
        "begin",
        "apply-sql:0001_registries",
        "log:0001_registries",
        "mark:0001_registries",
        "commit",
        "begin",
        "apply-sql:0002_partitioned",
        "log:0002_partitioned",
        "mark:0002_partitioned",
        "commit",
    ]


def test_tracebed_apply_through_does_not_skip_to_later_pending_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An already/non-pending target cannot expand a bounded reference apply."""

    from tracebed.stores.pg import migrate

    class FakeMigration:
        use_transactions = True

        def __init__(self, migration_id: str) -> None:
            self.id = migration_id
            self.hash = f"{migration_id}-hash"
            self.depends: set[object] = set()

        def load(self) -> None:
            return None

        def process_steps(self, _backend: object, _direction: str) -> None:
            raise AssertionError("no migration before the bounded target may run")

    class FakeBackend:
        has_transactional_ddl = True

        @contextmanager
        def lock(self) -> Iterator[None]:
            yield

        def ensure_internal_schema_updated(self) -> None:
            return None

        def to_apply(self, _migrations: object) -> list[FakeMigration]:
            return [later]

    target = FakeMigration("0001_registries")
    later = FakeMigration("0002_partitioned")
    fake_backend = FakeBackend()
    monkeypatch.setattr(migrate, "get_backend", lambda _dsn: fake_backend)
    monkeypatch.setattr(migrate, "read_all_migrations", lambda: [target, later])

    assert migrate.apply_migrations("postgresql://owner@db.example/tracebed", through=target.id) == []


def test_tracebed_rollback_uses_one_backend_transaction_not_yoyo_native_copy_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supported API never delegates a protected rollback to yoyo's split path."""

    from tracebed.stores.pg import migrate

    class FakeMigration:
        id = "0011_authority_cutover"
        hash = "expected-hash"
        use_transactions = True

        def load(self) -> None:
            return None

        def process_steps(self, backend: object, direction: str) -> None:
            assert backend is fake_backend
            assert direction == "rollback"
            fake_backend.events.append("rollback-sql")

    class FakeBackend:
        has_transactional_ddl = True

        def __init__(self) -> None:
            self.events: list[str] = []

        @contextmanager
        def lock(self) -> Iterator[None]:
            self.events.append("lock")
            yield

        @contextmanager
        def transaction(self) -> Iterator[None]:
            self.events.append("begin")
            try:
                yield
            except BaseException:
                self.events.append("rollback")
                raise
            else:
                self.events.append("commit")

        def ensure_internal_schema_updated(self) -> None:
            self.events.append("ensure")

        def to_rollback(self, _migrations: object) -> list[FakeMigration]:
            self.events.append("select-target")
            return [migration]

        def log_migration(self, received: FakeMigration, operation: str) -> None:
            assert received is migration and operation == "rollback"
            self.events.append("log")

        def unmark_one(self, received: FakeMigration, *, log: bool) -> None:
            assert received is migration and log is False
            self.events.append("unmark")

        def rollback_migrations(self, _targets: object) -> None:
            raise AssertionError("native yoyo rollback path must not be called")

        def copy(self) -> object:
            raise AssertionError("atomic rollback must not open yoyo's copied backend")

    migration = FakeMigration()
    fake_backend = FakeBackend()
    monkeypatch.setattr(migrate, "get_backend", lambda _dsn: fake_backend)
    monkeypatch.setattr(migrate, "read_all_migrations", lambda: [migration])
    monkeypatch.setattr(migrate, "version", lambda _distribution: "9.0.0")

    assert migrate.rollback_migrations("postgresql://owner@db.example/tracebed") == [
        "0011_authority_cutover"
    ]
    assert fake_backend.events == [
        "lock",
        "ensure",
        "select-target",
        "begin",
        "rollback-sql",
        "log",
        "unmark",
        "commit",
    ]


def test_tracebed_atomic_rollback_fails_closed_for_a_nontransactional_or_unpinned_yoyo_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The narrow yoyo-9 internals dependency cannot silently widen on upgrade."""

    from tracebed.stores.pg import migrate

    class FakeMigration:
        id = "0011_authority_cutover"
        hash = "expected-hash"
        use_transactions = True

        def load(self) -> None:
            return None

        def process_steps(self, _backend: object, _direction: str) -> None:
            raise AssertionError("must not execute with an unpinned yoyo contract")

    class FakeBackend:
        has_transactional_ddl = True

        @contextmanager
        def transaction(self) -> Iterator[None]:
            yield

        def log_migration(self, _migration: object, _operation: str) -> None:
            raise AssertionError("must not log with an unpinned yoyo contract")

        def unmark_one(self, _migration: object, *, log: bool) -> None:
            raise AssertionError("must not unmark with an unpinned yoyo contract")

    migration = FakeMigration()
    monkeypatch.setattr(migrate, "version", lambda _distribution: "9.0.1")
    with pytest.raises(RuntimeError, match=r"yoyo-migrations 9\.0\.0"):
        migrate._rollback_migration_atomically(FakeBackend(), migration, {migration.id: migration})

    monkeypatch.setattr(migrate, "version", lambda _distribution: "9.0.0")
    with pytest.raises(RuntimeError, match="target is not a packaged migration object"):
        migrate._rollback_migration_atomically(FakeBackend(), migration, {})

    migration.use_transactions = False
    with pytest.raises(RuntimeError, match="requires transactional migrations"):
        migrate._rollback_migration_atomically(
            FakeBackend(), migration, {migration.id: migration}
        )


class TestProjectProvisioningMigration:
    def test_paired_hashes_and_partial_idempotency_index(self) -> None:
        forward = _strip_sql_comments(_read("0007_project_provisioning.sql"))
        assert "ADD COLUMN provisioning_key_hash text" in forward
        assert "ADD COLUMN provisioning_request_hash text" in forward
        assert "project_provisioning_hashes_paired" in forward
        assert "provisioning_key_hash IS NULL AND provisioning_request_hash IS NULL" in forward
        assert "provisioning_key_hash IS NOT NULL AND provisioning_request_hash IS NOT NULL" in forward
        assert re.search(
            r"CREATE UNIQUE INDEX project_provisioning_key_hash_unique.*"
            r"WHERE provisioning_key_hash IS NOT NULL",
            forward,
            re.DOTALL,
        )

    def test_rollback_removes_only_provisioning_schema(self) -> None:
        rollback = _strip_sql_comments(_read("0007_project_provisioning.rollback.sql"))
        assert "DROP INDEX IF EXISTS project_provisioning_key_hash_unique" in rollback
        assert "DROP CONSTRAINT IF EXISTS project_provisioning_hashes_paired" in rollback
        assert "DROP COLUMN IF EXISTS provisioning_key_hash" in rollback
        assert "DROP COLUMN IF EXISTS provisioning_request_hash" in rollback


class TestTraceLearningJobMigration:
    def test_durable_job_parent_has_exact_identity_and_state_guards(self) -> None:
        from tracebed.domain.config import MAX_QUEUE_ATTEMPTS

        forward = _strip_sql_comments(_read("0008_trace_learning_job.sql"))
        block = _table_block(forward, "trace_learning_job")
        assert re.search(
            r"PRIMARY KEY\s*\(\s*project_id\s*,\s*run_id\s*,\s*pipeline\s*,\s*pipeline_version\s*\)",
            block,
            re.IGNORECASE,
        )
        assert re.search(r"trace_ended_at\s+timestamptz\s+NOT NULL", block, re.IGNORECASE)
        assert re.search(r"pipeline\s+~\s+'\^\[a-z\]\[a-z0-9_\]\{0,31\}\$'", block)
        assert "pipeline_version >= 1" in block
        assert "'pending', 'running', 'retry', 'succeeded', 'skipped', 'dead'" in block
        assert f"max_attempts BETWEEN 1 AND {MAX_QUEUE_ATTEMPTS}" in block
        assert "PARTITION BY LIST (project_id)" in block

    def test_null_sensitive_receipt_lease_and_attempt_guards_are_explicit(self) -> None:
        block = _table_block(_strip_sql_comments(_read("0008_trace_learning_job.sql")), "trace_learning_job")
        normalised = " ".join(block.split())
        # SQL CHECK passes UNKNOWN: each required value must therefore be tested
        # explicitly, rather than relying only on octet_length(NULL) = NULL.
        assert "result_digest IS NOT NULL AND octet_length(result_digest) = 32" in normalised
        assert "trace_digest IS NOT NULL AND octet_length(trace_digest) = 32" in normalised
        assert "state <> 'running' AND lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL" in normalised
        assert "state = 'pending' AND attempts = 0" in normalised
        assert "state = 'retry' AND attempts >= 1 AND attempts < max_attempts" in normalised
        assert "state = 'skipped' AND skip_code IS NOT NULL" in normalised
        assert "state <> 'skipped' AND skip_code IS NULL" in normalised
        assert "state IN ('retry', 'dead') AND last_error_code IS NOT NULL" in normalised
        assert "state NOT IN ('retry', 'dead') AND last_error_code IS NULL" in normalised

    def test_parent_rls_trigger_and_rollback_are_complete(self) -> None:
        forward = _strip_sql_comments(_read("0008_trace_learning_job.sql"))
        assert "ALTER TABLE trace_learning_job ENABLE ROW LEVEL SECURITY" in forward
        assert "ALTER TABLE trace_learning_job FORCE ROW LEVEL SECURITY" in forward
        assert "CREATE POLICY trace_learning_job_isolation" in forward
        assert "NULLIF(current_setting('tracebed.project_id', true), '')::uuid" in forward
        assert "REVOKE DELETE ON trace_learning_job FROM tracebed_app" in forward
        assert "GRANT SELECT, INSERT, UPDATE ON trace_learning_job TO tracebed_app" in forward
        assert "trace_learning_job_enforce_transition" in forward
        assert "trace learning job trace_digest is write-once" in forward
        assert "trace learning job first_started_at is write-once" in forward
        assert "trace learning job attempts advance only on claim" in forward
        assert "TG_OP = 'INSERT'" in forward
        assert "TG_OP = 'DELETE'" in forward
        assert "insert must be a pristine pending schedule row" in forward
        assert "BEFORE INSERT OR UPDATE OR DELETE" in forward
        rollback = _strip_sql_comments(_read("0008_trace_learning_job.rollback.sql"))
        assert "DROP TABLE IF EXISTS trace_learning_job CASCADE" in rollback
        assert "DROP FUNCTION IF EXISTS trace_learning_job_enforce_transition" in rollback


class TestTraceIndexTerminalFreezeMigration:
    def test_parent_trigger_and_app_delete_repair_are_explicit(self) -> None:
        forward = _strip_sql_comments(_read("0009_trace_index_terminal_freeze.sql"))
        assert "CREATE FUNCTION trace_index_enforce_terminal_immutability" in forward
        assert "BEFORE UPDATE OR DELETE ON trace_index" in forward
        assert "OLD.outcome_status IN ('ok', 'error', 'cancelled')" in forward
        assert "REVOKE DELETE ON trace_index FROM tracebed_app" in forward
        assert "GRANT SELECT, INSERT, UPDATE ON trace_index TO tracebed_app" in forward
        assert "FROM pg_inherits" in forward
        assert "REVOKE DELETE ON TABLE %s FROM tracebed_app" in forward

    def test_rollback_removes_guard_and_restores_prior_delete_grant(self) -> None:
        rollback = _strip_sql_comments(_read("0009_trace_index_terminal_freeze.rollback.sql"))
        assert "DROP TRIGGER IF EXISTS trace_index_terminal_immutability_guard ON trace_index" in rollback
        assert "DROP FUNCTION IF EXISTS trace_index_enforce_terminal_immutability" in rollback
        assert "GRANT DELETE ON trace_index TO tracebed_app" in rollback
        assert "GRANT DELETE ON TABLE %s TO tracebed_app" in rollback


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
        assert re.search(r"CREATE EXTENSION.*\bvchord_bm25\b", sql, re.IGNORECASE)
        assert re.search(r"CREATE EXTENSION.*\bpg_tokenizer\b", sql, re.IGNORECASE)

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
        "preset to empty", which is what the current owner bootstrap's
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
        source of truth for a credential the deployment bootstrap already
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

_ALL_MIGRATION_TABLES = REGISTRY_TABLES + _PARTITIONED_TABLES + (
    "trace_learning_job",
    "principal_grant",
    "run_owner",
    "authority_cutover_state",
    "work_queue",
    "dead_letter",
)


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
        assert applied == set(BOOTSTRAP_MIGRATION_IDS)

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
        assert "vchord_bm25" in names
        assert "pg_tokenizer" in names

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

    def test_trace_learning_job_rejects_partial_or_null_sensitive_shapes(
        self, pg_pool: Any, two_projects: tuple[Any, Any]
    ) -> None:
        """CHECK's three-valued logic must not admit malformed durable jobs.

        The SQL-text assertions above catch accidental removal of `IS NOT
        NULL`; this applies the migration and proves Postgres rejects partial
        running lease metadata and terminal rows missing their required
        receipts/digests.
        """
        import psycopg

        from tracebed.stores.pg.pool import scoped

        scope_a, _ = two_projects
        project_id = str(scope_a.project_id.value)
        invalid_rows = (
            # Pending cannot carry either kind of terminal/retry code.
            """
            INSERT INTO trace_learning_job (
                project_id, run_id, pipeline, pipeline_version, state, attempts,
                max_attempts, trace_ended_at, last_error_code
            ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, 'pending', 0, 3, now(), 'transient_failure')
            """,
            """
            INSERT INTO trace_learning_job (
                project_id, run_id, pipeline, pipeline_version, state, attempts,
                max_attempts, trace_ended_at, skip_code
            ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, 'pending', 0, 3, now(), 'manual_skip')
            """,
            # Running requires all three lease fields, not merely one.
            """
            INSERT INTO trace_learning_job (
                project_id, run_id, pipeline, pipeline_version, state, attempts,
                max_attempts, trace_ended_at, lease_token
            ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, 'running', 1, 3, now(), gen_random_uuid())
            """,
            """
            INSERT INTO trace_learning_job (
                project_id, run_id, pipeline, pipeline_version, state, attempts,
                max_attempts, trace_ended_at, first_started_at, lease_token, lease_owner,
                lease_expires_at, last_error_code
            ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, 'running', 1, 3, now(), now(),
                      gen_random_uuid(), 'migration-test', now() + interval '1 minute', 'transient_failure')
            """,
            # Retry requires an explicit safe error code after every failed
            # lease; an error-free retry would lose the audit reason.
            """
            INSERT INTO trace_learning_job (
                project_id, run_id, pipeline, pipeline_version, state, attempts,
                max_attempts, trace_ended_at, first_started_at
            ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, 'retry', 1, 3, now(), now())
            """,
            # A dead receipt cannot be NULL merely because octet_length(NULL)
            # evaluates to NULL (which a CHECK would otherwise accept).
            """
            INSERT INTO trace_learning_job (
                project_id, run_id, pipeline, pipeline_version, state, attempts,
                max_attempts, trace_ended_at, last_error_code, finished_at
            ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, 'dead', 1, 3, now(), 'lease_expired', now())
            """,
            # Succeeded needs a write-once trace digest as well as a receipt.
            """
            INSERT INTO trace_learning_job (
                project_id, run_id, pipeline, pipeline_version, state, attempts,
                max_attempts, trace_ended_at, result_digest, finished_at
            ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, 'succeeded', 1, 3, now(), decode(repeat('00', 32), 'hex'), now())
            """,
        )
        with pg_pool.connection() as conn:
            for statement in invalid_rows:
                with (
                    pytest.raises(psycopg.errors.CheckViolation),
                    conn.transaction(),
                    conn.cursor() as cur,
                ):
                    cur.execute("SELECT set_config('tracebed.project_id', %s, true)", (project_id,))
                    cur.execute(statement, (project_id,))

        with pg_pool.connection() as conn:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("SELECT set_config('tracebed.project_id', %s, true)", (project_id,))
                cur.execute(
                    """
                    INSERT INTO trace_learning_job (
                        project_id, run_id, pipeline, pipeline_version, trace_ended_at
                    ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, now())
                    RETURNING run_id
                    """,
                    (project_id,),
                )
                retry_row = cur.fetchone()
                assert retry_row is not None
                retry_run_id = retry_row[0]
                cur.execute(
                    """
                    INSERT INTO trace_learning_job (
                        project_id, run_id, pipeline, pipeline_version, trace_ended_at
                    ) VALUES (%s, gen_random_uuid(), 'tier_a', 1, now())
                    RETURNING run_id
                    """,
                    (project_id,),
                )
                dead_row = cur.fetchone()
                assert dead_row is not None
                dead_run_id = dead_row[0]
                for run_id in (retry_run_id, dead_run_id):
                    cur.execute(
                        """
                        UPDATE trace_learning_job
                        SET state = 'running', attempts = 1, first_started_at = now(),
                            lease_token = gen_random_uuid(), lease_owner = 'migration-test',
                            lease_expires_at = now() + interval '1 minute'
                        WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                        """,
                        (project_id, run_id),
                    )
                cur.execute(
                    """
                    UPDATE trace_learning_job
                    SET state = 'retry', available_at = now(), lease_token = NULL,
                        lease_owner = NULL, lease_expires_at = NULL, last_error_code = 'transient_failure'
                    WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                    """,
                    (project_id, retry_run_id),
                )
                cur.execute(
                    """
                    UPDATE trace_learning_job
                    SET state = 'dead', lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
                        last_error_code = 'max_attempts_exhausted',
                        result_digest = decode(repeat('00', 32), 'hex'), finished_at = now()
                    WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                    """,
                    (project_id, dead_run_id),
                )

            with (
                pytest.raises(psycopg.errors.CheckViolation),
                conn.transaction(),
                conn.cursor() as cur,
            ):
                cur.execute("SELECT set_config('tracebed.project_id', %s, true)", (project_id,))
                cur.execute(
                    """
                    UPDATE trace_learning_job SET last_error_code = NULL
                    WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                    """,
                    (project_id, retry_run_id),
                )

        # The owner can still DROP the whole partition for erasure, but no
        # caller may delete an individual durable ledger row.
        with pytest.raises(psycopg.errors.CheckViolation), scoped(pg_pool, scope_a.project_id) as conn:
            conn.execute(
                """
                DELETE FROM trace_learning_job
                WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                """,
                (project_id, retry_run_id),
            )

    def test_trace_learning_store_leases_are_scoped_idempotent_and_terminal(
        self, pg_pool: Any, two_projects: tuple[Any, Any]
    ) -> None:
        """Exercise the P2A1 DB-time path, including a final crashed lease.

        The second pipeline version proves the full four-part identity is
        respected.  The owner pool still enters through ``scoped()``, so this
        also proves RLS scope is set before each job operation.
        """
        import psycopg

        from tracebed.domain.ids import RunId
        from tracebed.stores.pg.pool import scoped
        from tracebed.stores.pg.trace_learning import TraceLearningJobStore
        from tracebed.workers.trace_learning import TIER_A_PIPELINE, result_receipt_digest

        scope_a, _ = two_projects
        project_id = scope_a.project_id
        run_id = RunId(uuid.uuid4())
        store = TraceLearningJobStore(pg_pool, lease_duration=timedelta(seconds=30))
        with scoped(pg_pool, project_id) as conn:
            for version in (1, 2):
                conn.execute(
                    """
                    INSERT INTO trace_learning_job
                        (project_id, run_id, pipeline, pipeline_version, state, attempts,
                         max_attempts, trace_ended_at)
                    VALUES (%(project_id)s, %(run_id)s, 'tier_a', %(version)s,
                            'pending', 0, 3, now())
                    """,
                    {
                        "project_id": project_id.value,
                        "run_id": run_id.value,
                        "version": version,
                    },
                )

        first = store.claim(project_id, TIER_A_PIPELINE, 1, "migration-proof", 10)
        version_two = store.claim(project_id, TIER_A_PIPELINE, 2, "migration-proof", 10)
        assert len(first) == len(version_two) == 1
        assert first[0].run_id == run_id and first[0].trace_ended_at is not None
        assert version_two[0].run_id == run_id

        # Retry pins the trace digest, and the old ownership token can never
        # renew/retry after the next claim.
        assert store.retry(first[0], timedelta(), "transient_failure", b"a" * 32).value == "retry"
        second = store.claim(project_id, TIER_A_PIPELINE, 1, "migration-proof", 1)[0]
        assert second.attempts == 2 and second.trace_digest == b"a" * 32
        assert store.renew(first[0]) is None
        assert store.retry(first[0], timedelta(), "transient_failure") is None

        # A healthy renewal prevents re-claim. Then emulate a crash: the next
        # claim sweeps the expired running row, rotates its token, and reaches
        # exactly its third/last delivery.
        renewed = store.renew(second)
        assert renewed is not None and renewed.lease_expires_at > second.lease_expires_at
        assert store.claim(project_id, TIER_A_PIPELINE, 1, "migration-proof", 1) == ()
        with scoped(pg_pool, project_id) as conn:
            conn.execute(
                """
                UPDATE trace_learning_job SET lease_expires_at = now() - interval '1 second'
                WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                """,
                (project_id.value, run_id.value),
            )
        third = store.claim(project_id, TIER_A_PIPELINE, 1, "migration-proof", 1)[0]
        assert third.attempts == 3 and third.lease_token != second.lease_token
        assert store.retry(third, timedelta(), "transient_failure").value == "dead"
        assert store.claim(project_id, TIER_A_PIPELINE, 1, "migration-proof", 1) == ()

        with scoped(pg_pool, project_id) as conn:
            row = conn.execute(
                """
                SELECT state, attempts, result_digest
                FROM trace_learning_job
                WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                """,
                (project_id.value, run_id.value),
            ).fetchone()
        assert row is not None and row[:2] == ("dead", 3)
        assert bytes(row[2]) == result_receipt_digest(
            project_id=project_id,
            run_id=run_id,
            pipeline=TIER_A_PIPELINE,
            pipeline_version=1,
            code="max_attempts_exhausted",
            trace_digest=b"a" * 32,
        )

        # The parent trigger makes every terminal row absorbing even for a
        # caller that attempted a raw SQL update outside the store.
        with pytest.raises(psycopg.errors.CheckViolation), scoped(pg_pool, project_id) as conn:
            conn.execute(
                """
                UPDATE trace_learning_job SET available_at = now()
                WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1
                """,
                (project_id.value, run_id.value),
            )

    def test_trace_learning_concurrent_claimers_receive_disjoint_leases(
        self, pg_dsn: str, two_projects: tuple[Any, Any]
    ) -> None:
        """`FOR UPDATE SKIP LOCKED` prevents a duplicate delivery race."""
        from tracebed.domain.ids import RunId
        from tracebed.stores.pg.pool import create_pool, scoped
        from tracebed.stores.pg.trace_learning import TraceLearningJobStore

        scope_a, _ = two_projects
        project_id = scope_a.project_id
        run_ids = (RunId(uuid.uuid4()), RunId(uuid.uuid4()))
        claim_pool = create_pool(pg_dsn, min_size=2, max_size=2)
        claim_pool.wait(timeout=5.0)
        store = TraceLearningJobStore(claim_pool, lease_duration=timedelta(seconds=30))
        try:
            with scoped(claim_pool, project_id) as conn:
                for run_id in run_ids:
                    conn.execute(
                        """
                        INSERT INTO trace_learning_job
                            (project_id, run_id, pipeline, pipeline_version, state, attempts,
                             max_attempts, trace_ended_at)
                        VALUES (%s, %s, 'claim_race', 1, 'pending', 0, 3, clock_timestamp())
                        """,
                        (project_id.value, run_id.value),
                    )

            barrier = threading.Barrier(3)
            results: list[tuple[RunId, ...]] = []
            errors: list[BaseException] = []

            def claim_one() -> None:
                try:
                    barrier.wait(timeout=2.0)
                    results.append(
                        tuple(
                            lease.run_id
                            for lease in store.claim(project_id, "claim_race", 1, "claim-racer", 1)
                        )
                    )
                except BaseException as exc:  # pragma: no cover - asserted below
                    errors.append(exc)

            workers = [threading.Thread(target=claim_one), threading.Thread(target=claim_one)]
            for worker in workers:
                worker.start()
            barrier.wait(timeout=2.0)
            for worker in workers:
                worker.join(timeout=3.0)
                assert not worker.is_alive()
            assert errors == []
            delivered = [run_id for claim in results for run_id in claim]
            assert len(delivered) == 2
            assert set(delivered) == set(run_ids)
        finally:
            claim_pool.close()

    def test_trace_learning_lease_fencing_rechecks_after_a_row_lock_wait(
        self,
        pg_dsn: str,
        two_projects: tuple[Any, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A transaction that began pre-expiry cannot revive a post-expiry lease.

        The holder takes the job row lock before the short lease expires.
        Each worker operation starts its own transaction and blocks in
        ``SELECT ... FOR UPDATE``; releasing the lock only after expiry proves
        the later UPDATE's ``clock_timestamp()`` predicate fences both renew
        and retry rather than trusting transaction-start ``now()``.
        """
        from contextlib import contextmanager

        from tracebed.domain.ids import RunId
        from tracebed.stores.pg import trace_learning as trace_learning_store_module
        from tracebed.stores.pg.pool import create_pool, scoped
        from tracebed.stores.pg.trace_learning import TraceLearningJobStore
        from tracebed.workers.trace_learning import TraceLearningLease

        scope_a, _ = two_projects
        project_id = scope_a.project_id
        pipeline = "fence_test"
        # Allow a cold pool to establish the second physical connection while
        # still ensuring its transaction starts before the lease expires.
        fence_pool = create_pool(pg_dsn, min_size=2, max_size=2)
        fence_pool.wait(timeout=5.0)
        store = TraceLearningJobStore(fence_pool, lease_duration=timedelta(seconds=3))
        worker_scope_entered = threading.Event()
        worker_pids: list[int] = []
        real_scoped = trace_learning_store_module.scoped

        @contextmanager
        def tracked_scoped(pool: Any, scope: Any) -> Any:
            with real_scoped(pool, scope) as conn:
                if threading.current_thread() is not threading.main_thread():
                    worker_pids.append(conn.info.backend_pid)
                    worker_scope_entered.set()
                yield conn

        monkeypatch.setattr(trace_learning_store_module, "scoped", tracked_scoped)

        def new_lease() -> TraceLearningLease:
            run_id = RunId(uuid.uuid4())
            with scoped(fence_pool, project_id) as conn:
                conn.execute(
                    """
                    INSERT INTO trace_learning_job
                        (project_id, run_id, pipeline, pipeline_version, state, attempts,
                         max_attempts, trace_ended_at)
                    VALUES (%s, %s, 'fence_test', 1, 'pending', 0, 3, clock_timestamp())
                    """,
                    (project_id.value, run_id.value),
                )
            return store.claim(project_id, pipeline, 1, "fence-test", 1)[0]

        def wait_until_worker_blocks(holder: Any, worker_pid: int) -> None:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                waiting = holder.execute(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM pg_locks
                        WHERE pid = %s AND NOT granted
                    )
                    """,
                    (worker_pid,),
                ).fetchone()
                if waiting is not None and waiting[0]:
                    return
                time.sleep(0.01)
            pytest.fail("lease operation did not block on the holder row lock before expiry")

        def prove_fenced(operation: str) -> None:
            lease = new_lease()
            started = threading.Event()
            results: list[object] = []
            errors: list[BaseException] = []
            worker_scope_entered.clear()
            worker_pids.clear()

            def call_store() -> None:
                started.set()
                try:
                    if operation == "renew":
                        results.append(store.renew(lease))
                    else:
                        results.append(store.retry(lease, timedelta(), "transient_failure"))
                except BaseException as exc:  # pragma: no cover - surfaced by assertion below
                    errors.append(exc)

            with scoped(fence_pool, project_id) as holder:
                holder.execute(
                    """
                    SELECT 1 FROM trace_learning_job
                    WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = 1
                    FOR UPDATE
                    """,
                    (project_id.value, lease.run_id.value, pipeline),
                )
                worker = threading.Thread(target=call_store)
                worker.start()
                assert started.wait(timeout=1.0)
                assert worker_scope_entered.wait(timeout=1.0)
                assert len(worker_pids) == 1
                wait_until_worker_blocks(holder, worker_pids[0])
                time.sleep(3.2)
            worker.join(timeout=3.0)
            assert not worker.is_alive()
            assert errors == []
            assert results == [None]
            with scoped(fence_pool, project_id) as conn:
                row = conn.execute(
                    """
                    SELECT state, lease_token FROM trace_learning_job
                    WHERE project_id = %s AND run_id = %s AND pipeline = %s AND pipeline_version = 1
                    """,
                    (project_id.value, lease.run_id.value, pipeline),
                ).fetchone()
            assert row == ("running", lease.lease_token)

        try:
            prove_fenced("renew")
            prove_fenced("retry")
        finally:
            fence_pool.close()

    def test_trace_learning_candidate_time_predicates_are_index_conditions(
        self, pg_pool: Any, two_projects: tuple[Any, Any]
    ) -> None:
        """The nonblocking claim/sweep scans keep their time terms indexable."""
        from tracebed.domain.ids import RunId
        from tracebed.stores.pg.pool import scoped

        scope_a, _ = two_projects
        project_id = scope_a.project_id
        ready_run_id = RunId(uuid.uuid4())
        lease_run_id = RunId(uuid.uuid4())
        with scoped(pg_pool, project_id) as conn:
            conn.execute(
                """
                INSERT INTO trace_learning_job
                    (project_id, run_id, pipeline, pipeline_version, state, attempts,
                     max_attempts, available_at, trace_ended_at)
                VALUES (%s, %s, 'plan_ready', 1, 'pending', 0, 3,
                        clock_timestamp(), clock_timestamp())
                """,
                (project_id.value, ready_run_id.value),
            )
            conn.execute(
                """
                INSERT INTO trace_learning_job
                    (project_id, run_id, pipeline, pipeline_version, state, attempts,
                     max_attempts, trace_ended_at)
                VALUES (%s, %s, 'plan_lease', 1, 'pending', 0, 3, clock_timestamp())
                """,
                (project_id.value, lease_run_id.value),
            )
            conn.execute(
                """
                UPDATE trace_learning_job
                SET state = 'running', attempts = 1, first_started_at = clock_timestamp(),
                    lease_token = gen_random_uuid(), lease_owner = 'plan-probe',
                    lease_expires_at = clock_timestamp() + interval '1 minute'
                WHERE project_id = %s AND run_id = %s AND pipeline = 'plan_lease'
                  AND pipeline_version = 1
                """,
                (project_id.value, lease_run_id.value),
            )
            conn.execute("SELECT set_config('enable_seqscan', 'off', true)")
            conn.execute("SELECT set_config('enable_bitmapscan', 'off', true)")

            def index_conditions(statement: str, pipeline: str) -> list[str]:
                row = conn.execute(
                    statement,
                    {"project_id": project_id.value, "pipeline": pipeline},
                ).fetchone()
                assert row is not None
                plan = row[0]
                assert isinstance(plan, list) and plan
                conditions: list[str] = []

                def visit(node: Any) -> None:
                    condition = node.get("Index Cond")
                    if isinstance(condition, str):
                        conditions.append(condition)
                    for child in node.get("Plans", []):
                        visit(child)

                visit(plan[0]["Plan"])
                return conditions

            ready_conditions = index_conditions(
                """
                EXPLAIN (FORMAT JSON, COSTS OFF)
                SELECT run_id FROM trace_learning_job
                WHERE project_id = %(project_id)s AND pipeline = %(pipeline)s
                  AND pipeline_version = 1 AND state IN ('pending', 'retry')
                  AND attempts < max_attempts AND available_at <= statement_timestamp()
                ORDER BY available_at, scheduled_at, run_id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                "plan_ready",
            )
            lease_conditions = index_conditions(
                """
                EXPLAIN (FORMAT JSON, COSTS OFF)
                SELECT run_id FROM trace_learning_job
                WHERE project_id = %(project_id)s AND pipeline = %(pipeline)s
                  AND pipeline_version = 1 AND state = 'running'
                  AND lease_expires_at <= statement_timestamp()
                ORDER BY lease_expires_at, scheduled_at, run_id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                "plan_lease",
            )

        assert any(
            "available_at" in condition and "statement_timestamp()" in condition
            for condition in ready_conditions
        )
        assert any(
            "lease_expires_at" in condition and "statement_timestamp()" in condition
            for condition in lease_conditions
        )

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
