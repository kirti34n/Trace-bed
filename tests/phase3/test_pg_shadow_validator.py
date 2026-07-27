"""`stores.pg.shadow_validator.ShadowValidatorRepo` against a real Postgres.

Two mandatory classes (per the port's test strategy):

  * `TestFakeParity` — the PG store and a faithful in-memory replica of `harness/closed_loop.py`'s
    `_Vault` (the fake the worker + harness were validated against) are driven through the same
    call sequence and asserted to produce identical observable results: the same `select_quarantined`
    projection, the same `quarantined -> candidate` persist with `status_changed_at := write.now`,
    and the same RAISE on a stale `from_status` (a re-apply of an already-`candidate` row).

  * `TestCrossProjectDenialUnderApp` — the acceptance bar. A `tracebed_app` connection (NOBYPASSRLS —
    an owner connection would hide a missing predicate) scoped to project B must NOT read project A's
    quarantined row, and a `persist` targeting A's id must affect zero rows (→ `StaleStatusTransition`)
    and leave A's row untouched.

Every test runs against a UNIQUELY-named scratch database created here, migrated, provisioned with
two projects, and dropped at the end — isolated from the shared `tracebed` DB and from sibling agents.
Skips cleanly when no Postgres is reachable (mirrors `tests/conftest.py::pg`).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from psycopg.conninfo import conninfo_to_dict
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.lifecycle import LifecycleWriter, StaleStatusTransition
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.stores.pg.shadow_validator import ShadowValidatorRepo
from tracebed.workers.shadow_validator import (
    QuarantinedMemoryRow,
    ShadowTransitionWrite,
    ShadowValidatorRepoPort,
)

pytestmark = pytest.mark.phase3

def _swap(dsn: str, **overrides: str) -> str:
    """Rebuild `dsn` as a `postgresql://` URL with the given fields overridden.

    `apply_migrations` needs a URL WITH a scheme (it string-replaces `postgresql://`);
    `psycopg.conninfo.make_conninfo` emits schemeless keyword format, which it rejects. So we
    parse and re-emit a URL, swapping `dbname` for the scratch DB and, for the isolation pool,
    `user`/`password` for the NOBYPASSRLS app role.
    """
    parts = conninfo_to_dict(dsn)
    parts.update(overrides)
    user = parts["user"]
    password = parts["password"]
    host = parts["host"]
    port = parts["port"]
    dbname = parts["dbname"]
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


_NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
_EARLIER = datetime(2026, 7, 26, 9, 0, tzinfo=UTC)
_EPOCH_ID = 7


# --------------------------------------------------------------------------- #
# A faithful in-memory replica of harness/closed_loop.py::_Vault's shadow contract.
# Reproduced (not imported) to keep the test free of the harness's argv/sys.path
# module-load side effects, but method-for-method identical to the two methods the
# worker + harness exercised: `select_quarantined_for_validation` and `persist`.
# --------------------------------------------------------------------------- #


@dataclass
class _VaultRow:
    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    provenance: Provenance
    status_changed_at: datetime | None
    is_failure_lesson: bool = False
    confirming_run_ids: tuple[RunId, ...] = ()


class _VaultFake:
    """The observable `ShadowValidatorRepoPort` contract `_Vault` exposes via `_ShadowRepoView`."""

    def __init__(self) -> None:
        self.rows: dict[MemoryId, _VaultRow] = {}

    def add(self, row: _VaultRow) -> None:
        self.rows[row.id] = row

    def select_quarantined(self, project_id: ProjectId) -> Sequence[QuarantinedMemoryRow]:
        return [
            QuarantinedMemoryRow(
                id=row.id,
                project_id=row.project_id,
                status=row.status,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                provenance=row.provenance,
                status_changed_at=row.status_changed_at,
                is_failure_lesson=row.is_failure_lesson,
                confirming_run_ids=row.confirming_run_ids,
            )
            for row in self.rows.values()
            if row.project_id == project_id and row.status is Status.QUARANTINED
        ]

    def persist(self, project_id: ProjectId, write: ShadowTransitionWrite) -> None:
        row = self.rows[write.memory_id]
        if row.project_id != project_id:
            raise TracebedError("cross-project status write")
        if row.status is not write.from_status:
            raise TracebedError(
                f"stale transition: row is {row.status.value!r}, write claims "
                f"{write.from_status.value!r}"
            )
        row.status = write.to_status
        row.status_changed_at = write.now


# --------------------------------------------------------------------------- #
# Scratch-DB harness.
# --------------------------------------------------------------------------- #


@dataclass
class _Scratch:
    dsn: str
    owner_pool: ConnectionPool
    project_a: ProjectId
    project_b: ProjectId


_INSERT_MEMORY_SQL = """
INSERT INTO memory_item (
    id, project_id, scope_type, mem_type, kind, lane, trust_tier, status,
    content, content_hash, token_count, provenance, scan_verdict_id,
    status_changed_at, shadow_confirm_runs
) VALUES (
    %(id)s, %(project_id)s, 'project_shared', %(mem_type)s, %(kind)s, 'operational',
    %(trust_tier)s, %(status)s, %(content)s, %(content_hash)s, %(token_count)s,
    %(provenance)s, %(scan_verdict_id)s, %(status_changed_at)s, %(shadow_confirm_runs)s
)
"""

_READ_STATUS_SQL = """
SELECT status, status_changed_at
FROM memory_item
WHERE project_id = %(project_id)s AND id = %(memory_id)s
"""

_READ_LOG_SQL = """
SELECT from_status, to_status, epoch_id
FROM memory_status_log
WHERE project_id = %(project_id)s AND memory_id = %(memory_id)s
"""


def _seed_quarantined(
    pool: ConnectionPool,
    project_id: ProjectId,
    *,
    memory_id: MemoryId,
    provenance: Provenance,
    confirming_run_ids: tuple[RunId, ...] = (),
    trust_tier: TrustTier = TrustTier.B,
    mem_type: MemType = MemType.LESSON,
    kind: str = "tool_failure_pattern",
) -> None:
    """Insert one `quarantined` `memory_item` row through a scoped (RLS-honouring) connection.

    Raw SQL is legal in a test file (`scripts/raw_sql_lint.py` walks only `src/`); the store
    under test issues none of this. `scoped()` sets the RLS GUC, without which FORCE RLS refuses
    the INSERT's `WITH CHECK`.
    """
    with scoped(pool, project_id) as conn:
        conn.execute(
            _INSERT_MEMORY_SQL,
            {
                "id": memory_id,
                "project_id": project_id,
                "mem_type": mem_type.value,
                "kind": kind,
                "trust_tier": trust_tier.value,
                "status": Status.QUARANTINED.value,
                "content": "an unconfirmed lesson",
                "content_hash": uuid.uuid4().hex,
                "token_count": 3,
                "provenance": Json(provenance.to_json()),
                "scan_verdict_id": uuid.uuid4(),
                "status_changed_at": _EARLIER,
                "shadow_confirm_runs": [str(r.value) for r in confirming_run_ids],
            },
        )


def _read_status(
    pool: ConnectionPool, project_id: ProjectId, memory_id: MemoryId
) -> tuple[str, datetime | None] | None:
    with scoped(pool, project_id) as conn:
        cur = conn.execute(_READ_STATUS_SQL, {"project_id": project_id, "memory_id": memory_id})
        row = cur.fetchone()
    if row is None:
        return None
    return (str(row[0]), row[1])


@pytest.fixture(scope="module")
def scratch() -> Iterator[_Scratch]:
    import psycopg

    from tracebed.stores.pg.migrate import apply_migrations
    from tracebed.stores.pg.partitions import create_project_partitions

    owner_dsn = os.environ.get("TB_STORAGE__PG_DSN")
    if not owner_dsn:
        pytest.skip("TB_STORAGE__PG_DSN is not set — no Postgres available")
    try:
        with psycopg.connect(owner_dsn, connect_timeout=1):
            pass
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"Postgres unreachable (TB_STORAGE__PG_DSN): {exc}")

    db_name = f"tb_shadow_{uuid.uuid4().hex}"
    admin = psycopg.connect(owner_dsn, autocommit=True)
    try:
        admin.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        admin.close()

    scratch_dsn = _swap(owner_dsn, dbname=db_name)
    pool: ConnectionPool | None = None
    try:
        try:
            apply_migrations(scratch_dsn)
        except Exception as exc:  # pragma: no cover - environment-dependent
            pytest.skip(f"could not bring the schema current: {exc.__class__.__name__}: {exc}")

        pool = create_pool(scratch_dsn)
        project_a = ProjectId(uuid.uuid4())
        project_b = ProjectId(uuid.uuid4())
        try:
            with pool.connection() as conn:
                create_project_partitions(conn, project_a)
                create_project_partitions(conn, project_b)
        except psycopg.errors.UndefinedObject as exc:  # pragma: no cover
            pytest.skip(f"pgvector/pg_textsearch access method unavailable: {exc}")

        yield _Scratch(scratch_dsn, pool, project_a, project_b)
    finally:
        if pool is not None:
            pool.close()
        admin = psycopg.connect(owner_dsn, autocommit=True)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')
        finally:
            admin.close()


def _store(pool: ConnectionPool) -> ShadowValidatorRepo:
    return ShadowValidatorRepo(pool, LifecycleWriter(pool, FakeClock(_NOW)))


# --------------------------------------------------------------------------- #
# (a) Fake-parity.
# --------------------------------------------------------------------------- #


class TestFakeParity:
    def test_store_satisfies_the_runtime_checkable_port(self, scratch: _Scratch) -> None:
        assert isinstance(_store(scratch.owner_pool), ShadowValidatorRepoPort)

    def test_select_projection_matches_the_vault_fake(self, scratch: _Scratch) -> None:
        pid = scratch.project_a
        mem_id = MemoryId(uuid.uuid4())
        runs = (RunId(uuid.uuid4()), RunId(uuid.uuid4()))
        prov = Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid.uuid4()),))
        _seed_quarantined(
            scratch.owner_pool, pid, memory_id=mem_id, provenance=prov, confirming_run_ids=runs
        )

        fake = _VaultFake()
        fake.add(
            _VaultRow(
                id=mem_id,
                project_id=pid,
                status=Status.QUARANTINED,
                trust_tier=TrustTier.B,
                mem_type=MemType.LESSON,
                provenance=prov,
                status_changed_at=_EARLIER,
                is_failure_lesson=False,
                confirming_run_ids=runs,
            )
        )

        got = [r for r in _store(scratch.owner_pool).select_quarantined(pid) if r.id == mem_id]
        want = list(fake.select_quarantined(pid))
        assert len(got) == 1
        g, w = got[0], want[0]
        # Identical observable projection, field-for-field.
        assert (g.id, g.project_id, g.status) == (w.id, w.project_id, w.status)
        assert g.trust_tier == w.trust_tier == TrustTier.B
        assert g.mem_type == w.mem_type == MemType.LESSON
        assert g.provenance == w.provenance  # jsonb round-trip through Provenance.from_json
        assert g.status_changed_at == w.status_changed_at == _EARLIER
        assert g.is_failure_lesson is w.is_failure_lesson is False  # fail-safe default, no column
        assert set(g.confirming_run_ids) == set(w.confirming_run_ids) == set(runs)

    def test_persist_moves_quarantined_to_candidate_like_the_fake(
        self, scratch: _Scratch
    ) -> None:
        pid = scratch.project_a
        mem_id = MemoryId(uuid.uuid4())
        prov = Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid.uuid4()),))
        _seed_quarantined(scratch.owner_pool, pid, memory_id=mem_id, provenance=prov)

        fake = _VaultFake()
        fake.add(
            _VaultRow(
                id=mem_id,
                project_id=pid,
                status=Status.QUARANTINED,
                trust_tier=TrustTier.B,
                mem_type=MemType.LESSON,
                provenance=prov,
                status_changed_at=_EARLIER,
            )
        )

        write = ShadowTransitionWrite(
            memory_id=mem_id,
            from_status=Status.QUARANTINED,
            to_status=Status.CANDIDATE,
            now=_NOW,
            epoch_id=_EPOCH_ID,
        )
        _store(scratch.owner_pool).persist(pid, write)
        fake.persist(pid, write)

        # Fake: row is now candidate, status_changed_at := now, and no longer quarantined.
        assert fake.rows[mem_id].status is Status.CANDIDATE
        assert fake.rows[mem_id].status_changed_at == _NOW
        assert fake.select_quarantined(pid) == []

        # PG: same observable result, read straight from the row.
        status, changed_at = _read_status(scratch.owner_pool, pid, mem_id)  # type: ignore[misc]
        assert status == Status.CANDIDATE.value
        assert changed_at == _NOW
        assert [r.id for r in _store(scratch.owner_pool).select_quarantined(pid)
                if r.id == mem_id] == []

        # And the transition was audited with the stamped epoch_id (the fake keeps no log;
        # this is the PG store's delegation to LifecycleWriter doing its documented job).
        with scoped(scratch.owner_pool, pid) as conn:
            log = conn.execute(_READ_LOG_SQL, {"project_id": pid, "memory_id": mem_id}).fetchall()
        assert log == [(Status.QUARANTINED.value, Status.CANDIDATE.value, _EPOCH_ID)]

    def test_stale_from_status_raises_on_both(self, scratch: _Scratch) -> None:
        """Re-applying an already-`candidate` row must RAISE (not silently no-op) — the store
        matches `_Vault`, whose `persist` raises on a stale `from_status`."""
        pid = scratch.project_a
        mem_id = MemoryId(uuid.uuid4())
        prov = Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid.uuid4()),))
        _seed_quarantined(scratch.owner_pool, pid, memory_id=mem_id, provenance=prov)

        fake = _VaultFake()
        fake.add(
            _VaultRow(
                id=mem_id,
                project_id=pid,
                status=Status.QUARANTINED,
                trust_tier=TrustTier.B,
                mem_type=MemType.LESSON,
                provenance=prov,
                status_changed_at=_EARLIER,
            )
        )
        write = ShadowTransitionWrite(
            memory_id=mem_id,
            from_status=Status.QUARANTINED,
            to_status=Status.CANDIDATE,
            now=_NOW,
            epoch_id=_EPOCH_ID,
        )
        _store(scratch.owner_pool).persist(pid, write)
        fake.persist(pid, write)

        # Second identical write: the row already moved. Both raise a TracebedError.
        with pytest.raises(StaleStatusTransition):
            _store(scratch.owner_pool).persist(pid, write)
        with pytest.raises(TracebedError):
            fake.persist(pid, write)

    def test_select_is_empty_for_a_project_with_no_quarantined_rows(
        self, scratch: _Scratch
    ) -> None:
        # project_b has never been seeded in this test.
        assert _store(scratch.owner_pool).select_quarantined(scratch.project_b) == []


# --------------------------------------------------------------------------- #
# (b) Cross-project denial under tracebed_app (NOBYPASSRLS).
# --------------------------------------------------------------------------- #


class TestCrossProjectDenialUnderApp:
    def test_project_b_can_neither_read_nor_write_project_a_rows(self, scratch: _Scratch) -> None:
        pid_a, pid_b = scratch.project_a, scratch.project_b
        mem_id = MemoryId(uuid.uuid4())
        prov = Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid.uuid4()),))
        _seed_quarantined(scratch.owner_pool, pid_a, memory_id=mem_id, provenance=prov)

        app_dsn = _swap(scratch.dsn, user="tracebed_app", password="tracebed_app_dev")
        app_pool = create_pool(app_dsn)
        try:
            store = _store(app_pool)

            # READ: B scoped, must not see A's quarantined row.
            assert [r.id for r in store.select_quarantined(pid_b) if r.id == mem_id] == []

            # WRITE: B scoped, targeting A's id → zero rows under RLS + predicate → raise.
            write = ShadowTransitionWrite(
                memory_id=mem_id,
                from_status=Status.QUARANTINED,
                to_status=Status.CANDIDATE,
                now=_NOW,
                epoch_id=_EPOCH_ID,
            )
            with pytest.raises(StaleStatusTransition):
                store.persist(pid_b, write)
        finally:
            app_pool.close()

        # A's row is untouched: still quarantined, original status_changed_at.
        status, changed_at = _read_status(scratch.owner_pool, pid_a, mem_id)  # type: ignore[misc]
        assert status == Status.QUARANTINED.value
        assert changed_at == _EARLIER
