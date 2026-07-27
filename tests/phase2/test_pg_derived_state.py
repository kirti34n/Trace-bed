"""`stores.pg.derived_state_store.DerivedStateStore` — the Postgres implementation
of `workers.derived_state.DerivedStateStorePort` (FIDELITY-AUDIT.md M3/M4).

Runs against a live Postgres via the scratch-DB recipe: `CREATE DATABASE <unique>`
→ `apply_migrations` → `create_project_partitions` for TWO projects A and B → run
→ `DROP DATABASE`. Skips cleanly (through the shared `pg` fixture) when no database
is reachable, so a machine with no Postgres gets one uniform skip rather than a red
setup error.

Two mandatory classes, per the port test strategy:

* **Fake-parity** — the PG store and the worker's in-memory `FakeDerivedStateStore`
  are driven through the same call sequences and asserted to produce identical
  observable results. `isinstance(store, DerivedStateStorePort)` is asserted against
  the `runtime_checkable` Protocol so a signature drift fails here rather than in a
  deployment. Encodes the acceptance points the spec names: `recent_versions`
  ascending / empty-on-absent-key, `append_version` durable `computed_at` round-trip
  (and the immutable-row raise on a duplicate version), and
  `prune_versions == DELETE ... WHERE version <= (max - keep)`.

* **Cross-project denial under `tracebed_app`** — a second connection opened as
  `tracebed_app` (NOBYPASSRLS, so a missing predicate is not masked the way the owner
  role would mask it). A row is seeded under project A; scoped to B, every read
  returns nothing for A's rows and every write targeting A's key leaves A's row
  unchanged — B cannot read OR write A's derived_state through this store.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg_pool import ConnectionPool

# The worker's in-memory contract double — the fake this store must match
# method-for-method.
from tests.phase2.test_derived_state import FakeDerivedStateStore
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.stores.pg.derived_state_store import DerivedStateStore
from tracebed.stores.pg.migrate import apply_migrations
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.workers.derived_state import DerivedStateStorePort, DerivedStateVersion

pytestmark = pytest.mark.phase2

_PROJECT_A = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_PROJECT_B = ProjectId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_AGENT = AgentTypeId.parse("cccccccc-cccc-cccc-cccc-cccccccccccc")
_KEY = "avg_tool_latency_ms"
_START = datetime(2026, 1, 1, tzinfo=UTC)


def _version(
    project_id: ProjectId,
    version: int,
    value: float,
    *,
    agent_type_id: AgentTypeId = _AGENT,
    key: str = _KEY,
    computed_at: datetime | None = None,
    delta_pct: float = 0.0,
    clamped: bool = False,
) -> DerivedStateVersion:
    return DerivedStateVersion(
        project_id=project_id,
        agent_type_id=agent_type_id,
        key=key,
        version=version,
        value=value,
        computed_at=computed_at or (_START + timedelta(days=version)),
        delta_pct=delta_pct,
        clamped=clamped,
    )


# --------------------------------------------------------------------------- #
# Scratch database: unique per run, dropped at the end (isolated from the shared
# tracebed DB and from any sibling agent's scratch DB).
# --------------------------------------------------------------------------- #


@pytest.fixture
def scratch_dsn(pg: str) -> Iterator[str]:
    """`CREATE DATABASE <unique>` off the owner DSN, migrate it, provision two
    project partitions, yield the DSN, `DROP DATABASE` at teardown."""
    db_name = f"tb_derived_state_{uuid.uuid4().hex[:16]}"
    admin = psycopg.connect(pg, autocommit=True)
    try:
        admin.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        admin.close()

    # Keep the scratch DSN in the same URL form as the owner DSN: yoyo (via
    # `apply_migrations`) requires a scheme, which `make_conninfo`'s keyword form
    # does not carry. Only the trailing database segment changes.
    base, sep, query = pg.partition("?")
    dsn = base.rsplit("/", 1)[0] + "/" + db_name + sep + query
    try:
        apply_migrations(dsn)
        pool = create_pool(dsn)
        try:
            with pool.connection() as conn:
                create_project_partitions(conn, _PROJECT_A)
                create_project_partitions(conn, _PROJECT_B)
        finally:
            pool.close()
        yield dsn
    finally:
        admin = psycopg.connect(pg, autocommit=True)
        try:
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (db_name,),
            )
            admin.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            admin.close()


@pytest.fixture
def owner_pool(scratch_dsn: str) -> Iterator[ConnectionPool]:
    pool = create_pool(scratch_dsn)
    try:
        yield pool
    finally:
        pool.close()


@pytest.fixture
def store(owner_pool: ConnectionPool) -> DerivedStateStore:
    return DerivedStateStore(owner_pool)


# --------------------------------------------------------------------------- #
# (a) Fake-parity.
# --------------------------------------------------------------------------- #


class TestFakeParity:
    def test_the_pg_store_satisfies_the_declared_store_port(
        self, store: DerivedStateStore
    ) -> None:
        assert isinstance(store, DerivedStateStorePort)

    def test_recent_versions_is_empty_for_a_key_never_written(
        self, store: DerivedStateStore
    ) -> None:
        fake = FakeDerivedStateStore()
        assert list(store.recent_versions(_PROJECT_A, _AGENT, _KEY)) == []
        assert list(fake.recent_versions(_PROJECT_A, _AGENT, _KEY)) == []

    def test_recent_versions_returns_the_complete_set_ascending(
        self, store: DerivedStateStore
    ) -> None:
        """Appended out of version order; both stores return version-ascending."""
        fake = FakeDerivedStateStore()
        for v in (3, 1, 2):
            row = _version(_PROJECT_A, v, 100.0 + v)
            store.append_version(row)
            fake.append_version(row)

        pg_rows = list(store.recent_versions(_PROJECT_A, _AGENT, _KEY))
        fake_rows = list(fake.recent_versions(_PROJECT_A, _AGENT, _KEY))
        assert [r.version for r in pg_rows] == [1, 2, 3]
        assert pg_rows == fake_rows

    def test_append_version_round_trips_every_field_including_computed_at(
        self, store: DerivedStateStore
    ) -> None:
        """`computed_at` is the load-bearing field (the writer's divergence
        windows key off it) — it must round-trip durably and tz-aware, exactly
        as the fake preserves it."""
        computed_at = datetime(2026, 3, 3, 4, 5, 6, tzinfo=UTC)
        row = _version(
            _PROJECT_A, 1, 123.5, computed_at=computed_at, delta_pct=-7.25, clamped=True
        )
        fake = FakeDerivedStateStore()
        store.append_version(row)
        fake.append_version(row)

        got = store.recent_versions(_PROJECT_A, _AGENT, _KEY)[0]
        assert got == fake.recent_versions(_PROJECT_A, _AGENT, _KEY)[0]
        assert got.computed_at == computed_at
        assert got.computed_at.tzinfo is not None
        assert got.value == 123.5
        assert got.delta_pct == -7.25
        assert got.clamped is True

    def test_appending_a_duplicate_version_raises(self, store: DerivedStateStore) -> None:
        """The port documents append as immutable: no ON CONFLICT, so a repeated
        version number violates the PK and raises rather than overwriting."""
        store.append_version(_version(_PROJECT_A, 1, 100.0))
        with pytest.raises(psycopg.errors.UniqueViolation):
            store.append_version(_version(_PROJECT_A, 1, 999.0))

    def test_distinct_keys_and_agent_types_are_independent(
        self, store: DerivedStateStore
    ) -> None:
        other_agent = AgentTypeId.parse("dddddddd-dddd-dddd-dddd-dddddddddddd")
        store.append_version(_version(_PROJECT_A, 1, 10.0, key="key_a"))
        store.append_version(_version(_PROJECT_A, 1, 20.0, key="key_b"))
        store.append_version(_version(_PROJECT_A, 1, 30.0, agent_type_id=other_agent))

        assert [r.value for r in store.recent_versions(_PROJECT_A, _AGENT, "key_a")] == [10.0]
        assert [r.value for r in store.recent_versions(_PROJECT_A, _AGENT, "key_b")] == [20.0]
        assert [
            r.value for r in store.recent_versions(_PROJECT_A, other_agent, _KEY)
        ] == [30.0]

    def test_prune_keeps_exactly_the_newest_keep_versions(
        self, store: DerivedStateStore
    ) -> None:
        """Mirrors `test_version_pruning_keeps_exactly_keep_versions`: 12 versions,
        keep=5 → [8, 9, 10, 11, 12] survive, oldest dropped."""
        fake = FakeDerivedStateStore()
        for v in range(1, 13):
            row = _version(_PROJECT_A, v, 100.0 + v)
            store.append_version(row)
            fake.append_version(row)

        store.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=5)
        fake.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=5)

        pg_rows = list(store.recent_versions(_PROJECT_A, _AGENT, _KEY))
        assert [r.version for r in pg_rows] == [8, 9, 10, 11, 12]
        assert pg_rows == fake.recent_versions(_PROJECT_A, _AGENT, _KEY)

    def test_prune_keep_one_leaves_the_newest_row_the_rate_bound_reads(
        self, store: DerivedStateStore
    ) -> None:
        """Mirrors `test_pruning_never_deletes_the_row_the_rate_bound_reads`:
        keep=1 leaves exactly the highest-version row."""
        fake = FakeDerivedStateStore()
        for v in range(1, 6):
            row = _version(_PROJECT_A, v, 100.0 + v)
            store.append_version(row)
            fake.append_version(row)

        store.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=1)
        fake.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=1)

        pg_rows = list(store.recent_versions(_PROJECT_A, _AGENT, _KEY))
        assert [r.version for r in pg_rows] == [5]
        assert pg_rows == fake.recent_versions(_PROJECT_A, _AGENT, _KEY)

    def test_prune_with_keep_at_or_above_count_deletes_nothing(
        self, store: DerivedStateStore
    ) -> None:
        fake = FakeDerivedStateStore()
        for v in range(1, 4):
            row = _version(_PROJECT_A, v, 100.0 + v)
            store.append_version(row)
            fake.append_version(row)

        store.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=3)
        fake.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=3)
        assert [r.version for r in store.recent_versions(_PROJECT_A, _AGENT, _KEY)] == [1, 2, 3]

        store.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=10)
        fake.prune_versions(_PROJECT_A, _AGENT, _KEY, keep=10)
        assert [r.version for r in store.recent_versions(_PROJECT_A, _AGENT, _KEY)] == [1, 2, 3]

    def test_prune_on_an_absent_key_is_a_noop(self, store: DerivedStateStore) -> None:
        # max(version) over no rows is NULL, `NULL - keep` is NULL, `version <= NULL`
        # is never true — the delete affects nothing and does not raise.
        store.prune_versions(_PROJECT_A, _AGENT, "never_written", keep=5)
        assert list(store.recent_versions(_PROJECT_A, _AGENT, "never_written")) == []


# --------------------------------------------------------------------------- #
# (b) Cross-project denial under `tracebed_app` (NOBYPASSRLS).
# --------------------------------------------------------------------------- #


@pytest.fixture
def app_pool(scratch_dsn: str) -> Iterator[ConnectionPool]:
    """A pool connected as `tracebed_app` — NOBYPASSRLS, so RLS is enforced and a
    dropped predicate is not masked the way the owner role would mask it."""
    app_dsn = make_conninfo(scratch_dsn, user="tracebed_app", password="tracebed_app_dev")
    pool = create_pool(app_dsn)
    try:
        yield pool
    finally:
        pool.close()


class TestCrossProjectDenialUnderApp:
    def test_project_b_cannot_read_or_write_project_a_rows(
        self, owner_pool: ConnectionPool, app_pool: ConnectionPool
    ) -> None:
        # Seed A's history via the app role itself (proves A can write its own).
        app_store = DerivedStateStore(app_pool)
        for v in range(1, 4):
            app_store.append_version(_version(_PROJECT_A, v, 100.0 + v))
        seeded = list(app_store.recent_versions(_PROJECT_A, _AGENT, _KEY))
        assert [r.version for r in seeded] == [1, 2, 3]

        # Scoped to B, A's rows are invisible on every read. The store's own
        # `append_version` scopes on `version.project_id`, so a cross-project
        # write is not even expressible through its API — the RLS WITH CHECK
        # backstop is proven directly below instead, bypassing that self-scoping.
        assert list(app_store.recent_versions(_PROJECT_B, _AGENT, _KEY)) == []

        # RLS backstop: a connection scoped to B literally cannot land an
        # A-owned row. The policy is USING-only, which Postgres also applies as
        # the INSERT WITH CHECK, so project_id=A under GUC=B raises
        # InsufficientPrivilege ("new row violates row-level security policy").
        # `value` is cast to jsonb explicitly so the ONLY reason this fails is
        # the RLS check, never a datatype mismatch that would mask it.
        with (
            pytest.raises(psycopg.errors.InsufficientPrivilege),
            scoped(app_pool, _PROJECT_B) as conn,
        ):
            conn.execute(
                "INSERT INTO derived_state "
                "(project_id, agent_type_id, key, version, value, computed_at, "
                "delta_pct, clamped) VALUES "
                "(%(pid)s, %(aid)s, %(key)s, 99, to_jsonb(%(val)s::double precision), "
                "%(ca)s, 0.0, false)",
                {
                    "pid": _PROJECT_A,
                    "aid": _AGENT,
                    "key": _KEY,
                    "val": 7.0,
                    "ca": _START,
                },
            )

        # prune from B's scope against A's key deletes nothing of A's.
        app_store.prune_versions(_PROJECT_B, _AGENT, _KEY, keep=1)

        # A's history is completely unchanged, verified from the owner scope.
        owner_store = DerivedStateStore(owner_pool)
        after = list(owner_store.recent_versions(_PROJECT_A, _AGENT, _KEY))
        assert [r.version for r in after] == [1, 2, 3]
        assert [r.value for r in after] == [101.0, 102.0, 103.0]

    def test_a_prune_scoped_to_b_never_touches_a_even_at_keep_one(
        self, owner_pool: ConnectionPool, app_pool: ConnectionPool
    ) -> None:
        """The dangerous shape: a keep=1 prune from B's scope must not delete A's
        older versions. RLS + the explicit predicate confine the DELETE to B's
        (empty) partition."""
        owner_store = DerivedStateStore(owner_pool)
        for v in range(1, 6):
            owner_store.append_version(_version(_PROJECT_A, v, 100.0 + v))

        app_store = DerivedStateStore(app_pool)
        app_store.prune_versions(_PROJECT_B, _AGENT, _KEY, keep=1)

        after = list(owner_store.recent_versions(_PROJECT_A, _AGENT, _KEY))
        assert [r.version for r in after] == [1, 2, 3, 4, 5]
