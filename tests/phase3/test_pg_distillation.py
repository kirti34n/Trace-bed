"""`stores.pg.distillation.KnownDistillationRepo` -- the Postgres implementation of
`workers.distiller.KnownDistillationPort` (FIDELITY-AUDIT.md M3; the in-code CONTRACT GAP the
worker's own docstring reports: "no method on `stores.pg.repo.Repo` satisfies this today").

Runs against a live Postgres via the scratch-DB recipe: `CREATE DATABASE <unique>` ->
`apply_migrations` -> `create_project_partitions` for TWO projects A and B -> run ->
`DROP DATABASE`. Skips cleanly (through the shared `pg` fixture) when no database is reachable,
so a machine with no Postgres gets one uniform skip rather than a red setup error.

Two mandatory classes, per the port test strategy:

* **Fake-parity** -- the PG store and the worker's in-memory `_FakeKnownDistillations` are driven
  through the same call sequence and asserted to produce identical observable results.
  `isinstance(store, KnownDistillationPort)` is asserted against the `runtime_checkable` Protocol
  so a signature drift fails here rather than in a deployment. Encodes the spec's acceptance
  points: one `ExistingDistillation` per `(memory_id, hash)` pair, deterministic
  `ORDER BY created_at, id` with provenance-array order preserved within a memory, and the
  `provenance->>'class' = 'distiller'` filter (a non-distiller row is never returned).

* **Cross-project denial under `tracebed_app`** (NOBYPASSRLS, so a dropped predicate is not
  masked the way the owner role would mask it). A distillation is seeded under project A; scoped
  to B, `existing_signatures(B)` returns nothing referencing A's memory_id or hash, and a direct
  app-role read of A's row from B's scope returns zero rows -- B cannot read A's distillations
  through this store, so the worker's foreign-project backstop (`_find_duplicate`) is never fed a
  cross-project row.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Sequence

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg_pool import ConnectionPool

# The worker's in-memory contract double -- the fake this store must match method-for-method.
from tests.phase3.test_distiller import _FakeKnownDistillations
from tracebed.core.scans import ScanContext, scan
from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.ids import MemoryId, ProjectId, RunId, mint_run_id
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.distillation import KnownDistillationRepo
from tracebed.stores.pg.migrate import apply_migrations
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.stores.pg.repo import Repo
from tracebed.workers.distiller import (
    ExistingDistillation,
    KnownDistillationPort,
)

pytestmark = pytest.mark.phase3

_PROJECT_A = ProjectId.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_PROJECT_B = ProjectId.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

# Four distinct, well-formed SIG_HASH_LEN (40-byte) signatures. The store never clusters them --
# clustering is the worker's job; the store only round-trips the bytes -- so any distinct 40-byte
# values suffice. `bytes([n]) * 40` is a valid 40-byte signature that `ExistingDistillation`'s
# length check accepts.
_HASH_A1A = bytes([0x11]) * 40
_HASH_A1B = bytes([0x22]) * 40
_HASH_A2 = bytes([0x33]) * 40
_HASH_B1 = bytes([0x44]) * 40


# --------------------------------------------------------------------------- #
# Scratch database: unique per run, dropped at the end (isolated from the shared
# tracebed DB and from any sibling agent's scratch DB).
# --------------------------------------------------------------------------- #


@pytest.fixture
def scratch_dsn(pg: str) -> Iterator[str]:
    """`CREATE DATABASE <unique>` off the owner DSN, migrate it, provision two
    project partitions, yield the DSN, `DROP DATABASE` at teardown."""
    db_name = f"tb_distillation_{uuid.uuid4().hex[:16]}"
    admin = psycopg.connect(pg, autocommit=True)
    try:
        admin.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        admin.close()

    # Keep the scratch DSN in the same URL form as the owner DSN: yoyo (via `apply_migrations`)
    # requires a scheme, which `make_conninfo`'s keyword form does not carry. Only the trailing
    # database segment changes.
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
def store(owner_pool: ConnectionPool) -> KnownDistillationRepo:
    return KnownDistillationRepo(owner_pool)


# --------------------------------------------------------------------------- #
# Seeding: distiller `memory_item` rows written through the real `Repo` so
# provenance/scan-verdict validation is exercised rather than bypassed.
# --------------------------------------------------------------------------- #


def _seed_distillation(
    pool: ConnectionPool,
    clock: FakeClock,
    project_id: ProjectId,
    input_sig_hashes: Sequence[bytes],
    *,
    provenance_class: ProvenanceClass = ProvenanceClass.DISTILLER,
    content: str = "retry the flaky upload with jittered backoff",
) -> MemoryId:
    """Insert one quality-lane distillation carrying `input_sig_hashes` in its provenance.

    The clock is advanced after each insert so `created_at` is strictly monotonic per insert,
    which is what makes `ORDER BY created_at, id` reproduce insertion order deterministically
    (the store's fake-fidelity contract: the first-seeded same-cluster entry must win).
    """
    repo = Repo(pool, clock)
    run_ids = tuple(mint_run_id() for _ in range(max(1, len(input_sig_hashes))))
    item = NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="k",
        lane=Lane.QUALITY,
        trust_tier=TrustTier.B,
        status=Status.QUARANTINED,
        content=content,
        token_count=len(content.split()),
        provenance=Provenance(
            cls=provenance_class,
            trace_ids=run_ids,
            input_sig_hashes=tuple(input_sig_hashes),
        ),
    )
    verdict = scan(
        content,
        context=ScanContext(
            project_id=project_id,
            mem_type=item.mem_type,
            trust_tier=item.trust_tier,
            provenance_class=item.provenance.cls,
            lane=Lane.QUALITY,
        ),
    ).verdict()
    mem_id = repo.insert_memory_item(project_id, item, verdict)
    clock.advance(seconds=1)
    return mem_id


def _seed_parser(
    pool: ConnectionPool, clock: FakeClock, project_id: ProjectId
) -> MemoryId:
    """A non-distiller (`parser`) `memory_item` row -- the `provenance->>'class'` filter must
    exclude it even though it lives in the same partition."""
    repo = Repo(pool, clock)
    content = "a parser note that is not a distillation"
    run_id: RunId = mint_run_id()
    item = NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="k",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.B,
        status=Status.QUARANTINED,
        content=content,
        token_count=len(content.split()),
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_id,)),
    )
    verdict = scan(
        content,
        context=ScanContext(
            project_id=project_id,
            mem_type=item.mem_type,
            trust_tier=item.trust_tier,
            provenance_class=item.provenance.cls,
            lane=Lane.OPERATIONAL,
        ),
    ).verdict()
    mem_id = repo.insert_memory_item(project_id, item, verdict)
    clock.advance(seconds=1)
    return mem_id


# --------------------------------------------------------------------------- #
# (a) Fake-parity.
# --------------------------------------------------------------------------- #


class TestFakeParity:
    def test_the_pg_store_satisfies_the_declared_store_port(
        self, store: KnownDistillationRepo
    ) -> None:
        assert isinstance(store, KnownDistillationPort)

    def test_existing_signatures_is_empty_for_a_project_with_no_distillations(
        self, store: KnownDistillationRepo
    ) -> None:
        fake = _FakeKnownDistillations()
        assert list(store.existing_signatures(_PROJECT_A)) == []
        assert list(fake.existing_signatures(_PROJECT_A)) == []

    def test_returns_one_entry_per_hash_in_deterministic_order(
        self, store: KnownDistillationRepo, owner_pool: ConnectionPool
    ) -> None:
        """One `ExistingDistillation` per `(memory_id, hash)` pair, `ORDER BY created_at, id`
        across memories with provenance-array order preserved within a memory. Driven against
        the worker's own fake seeded with the exact expected sequence."""
        clock = FakeClock()
        mem_a1 = _seed_distillation(owner_pool, clock, _PROJECT_A, [_HASH_A1A, _HASH_A1B])
        mem_a2 = _seed_distillation(owner_pool, clock, _PROJECT_A, [_HASH_A2])

        expected = [
            ExistingDistillation(_PROJECT_A, mem_a1, _HASH_A1A),
            ExistingDistillation(_PROJECT_A, mem_a1, _HASH_A1B),
            ExistingDistillation(_PROJECT_A, mem_a2, _HASH_A2),
        ]
        fake = _FakeKnownDistillations(expected)

        pg_rows = list(store.existing_signatures(_PROJECT_A))
        assert pg_rows == expected
        assert pg_rows == list(fake.existing_signatures(_PROJECT_A))
        # Every entry carries the scoped project id -- the property the worker's foreign-project
        # sweep relies on never being violated.
        assert {row.project_id for row in pg_rows} == {_PROJECT_A}

    def test_non_distiller_rows_are_excluded_by_the_provenance_filter(
        self, store: KnownDistillationRepo, owner_pool: ConnectionPool
    ) -> None:
        clock = FakeClock()
        mem_a1 = _seed_distillation(owner_pool, clock, _PROJECT_A, [_HASH_A1A])
        _seed_parser(owner_pool, clock, _PROJECT_A)  # must never appear

        pg_rows = list(store.existing_signatures(_PROJECT_A))
        assert pg_rows == [ExistingDistillation(_PROJECT_A, mem_a1, _HASH_A1A)]

    def test_each_project_sees_only_its_own_distillations(
        self, store: KnownDistillationRepo, owner_pool: ConnectionPool
    ) -> None:
        clock = FakeClock()
        mem_a = _seed_distillation(owner_pool, clock, _PROJECT_A, [_HASH_A1A])
        mem_b = _seed_distillation(owner_pool, clock, _PROJECT_B, [_HASH_B1])

        assert list(store.existing_signatures(_PROJECT_A)) == [
            ExistingDistillation(_PROJECT_A, mem_a, _HASH_A1A)
        ]
        assert list(store.existing_signatures(_PROJECT_B)) == [
            ExistingDistillation(_PROJECT_B, mem_b, _HASH_B1)
        ]


# --------------------------------------------------------------------------- #
# (b) Cross-project denial under `tracebed_app` (NOBYPASSRLS).
# --------------------------------------------------------------------------- #


@pytest.fixture
def app_pool(scratch_dsn: str) -> Iterator[ConnectionPool]:
    """A pool connected as `tracebed_app` -- NOBYPASSRLS, so RLS is enforced and a dropped
    predicate is not masked the way the owner role would mask it."""
    app_dsn = make_conninfo(scratch_dsn, user="tracebed_app", password="tracebed_app_dev")
    pool = create_pool(app_dsn)
    try:
        yield pool
    finally:
        pool.close()


class TestCrossProjectDenialUnderApp:
    def test_project_b_cannot_read_project_a_distillations_through_the_store(
        self, owner_pool: ConnectionPool, app_pool: ConnectionPool
    ) -> None:
        clock = FakeClock()
        mem_a = _seed_distillation(owner_pool, clock, _PROJECT_A, [_HASH_A1A, _HASH_A1B])

        app_store = KnownDistillationRepo(app_pool)

        # B has no distillations of its own: scoped to B, the store sees nothing -- and in
        # particular nothing referencing A's memory_id or A's hashes.
        b_rows = list(app_store.existing_signatures(_PROJECT_B))
        assert b_rows == []
        assert all(row.project_id == _PROJECT_B for row in b_rows)
        assert mem_a not in {row.memory_id for row in b_rows}
        assert {_HASH_A1A, _HASH_A1B}.isdisjoint({row.input_signature_hash for row in b_rows})

        # Seed a distillation under B too, then re-check: B's scope returns ONLY B's row, still
        # nothing of A's -- the worker's foreign-project backstop is never fed a cross-project row.
        mem_b = _seed_distillation(owner_pool, clock, _PROJECT_B, [_HASH_B1])
        b_rows = list(app_store.existing_signatures(_PROJECT_B))
        assert b_rows == [ExistingDistillation(_PROJECT_B, mem_b, _HASH_B1)]
        assert mem_a not in {row.memory_id for row in b_rows}
        assert {_HASH_A1A, _HASH_A1B}.isdisjoint({row.input_signature_hash for row in b_rows})

    def test_a_direct_app_role_read_of_a_row_from_b_scope_returns_zero(
        self, owner_pool: ConnectionPool, app_pool: ConnectionPool
    ) -> None:
        """The RLS backstop directly: even a raw read for A's exact memory id, issued on an
        app-role connection scoped to B, returns zero rows -- the predicate and the FORCED RLS
        policy both confine the read to B's partition."""
        clock = FakeClock()
        mem_a = _seed_distillation(owner_pool, clock, _PROJECT_A, [_HASH_A1A])

        with scoped(app_pool, _PROJECT_B) as conn:
            cur = conn.execute(
                "SELECT count(*) FROM memory_item "
                "WHERE project_id = %(project_id)s AND id = %(memory_id)s",
                {"project_id": _PROJECT_A, "memory_id": mem_a},
            )
            row = cur.fetchone()
        assert row is not None
        assert row[0] == 0

        # And from A's own scope the row is present -- proving the zero above is denial, not an
        # empty database.
        with scoped(owner_pool, _PROJECT_A) as conn:
            cur = conn.execute(
                "SELECT count(*) FROM memory_item "
                "WHERE project_id = %(project_id)s AND id = %(memory_id)s",
                {"project_id": _PROJECT_A, "memory_id": mem_a},
            )
            row = cur.fetchone()
        assert row is not None
        assert row[0] == 1
