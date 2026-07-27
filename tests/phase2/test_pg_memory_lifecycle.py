"""`stores.pg.memory_lifecycle.MemoryLifecycleRepo` — the Postgres store behind the shared
`workers.invalidator.MemoryLifecycleRepoPort` (Invalidator + RevalidationWorker + sweeps).

Two mandatory test classes, per the port's acceptance bar:

(a) Fake-parity — assert the store satisfies the `@runtime_checkable` Protocol, then drive the
    same call sequence against the PG store and an in-memory reference vault that encodes the
    UNION of the three `_FakeRepo`s the workers were validated against
    (tests/phase2/test_invalidator.py, test_revalidation.py, test_ttl_sweeps.py), asserting
    identical observable results. Plus the specific acceptance points the spec pins: the jsonb
    `?|` provenance UNION (a RunId and a lowercase-hex input_sig_hash round-trip), the field-touch
    rule (from==to leaves `status_changed_at` untouched; a real transition sets it to `write.now`),
    the conditional strike_count/q_value/last_revalidated_at columns, and the inclusive `<=` on
    `COALESCE(last_retrieved_at, created_at)` for VALIDATED rows only.

(b) Cross-project denial under `tracebed_app` (NOBYPASSRLS — the owner role would hide a missing
    predicate). Seed a row in project A; scope the store to B and assert every read returns nothing
    for A's rows and every write targeting A's id mutates nothing (raising `StaleStatusTransition`),
    leaving A's row unchanged. Positive controls (the same store scoped to A does see A's row)
    guard that the denial is about the project, not a blanket failure.

Runs against a private, uniquely-named scratch database (create -> apply_migrations ->
create_project_partitions for two projects -> test -> DROP), isolated from the shared tracebed DB
and from sibling agents. Skips cleanly when no Postgres is reachable, exactly like every other
integration test in this repository.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = [pytest.mark.phase2, pytest.mark.integration]

# Import guard: nothing here should error at COLLECTION time on a machine with no psycopg / no DB
# (the repository's §12 rule). psycopg is a hard dependency, so importing it is safe; the
# connection attempt lives inside the fixture, which skips.
psycopg = pytest.importorskip("psycopg")
from psycopg.conninfo import make_conninfo  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402
from psycopg.types.json import Json  # noqa: E402

from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier  # noqa: E402
from tracebed.domain.ids import MemoryId, ProjectId, RunId  # noqa: E402
from tracebed.domain.memory import Provenance  # noqa: E402
from tracebed.domain.state_machine import Status  # noqa: E402
from tracebed.stores.pg.lifecycle import StaleStatusTransition  # noqa: E402
from tracebed.stores.pg.memory_lifecycle import MemoryLifecycleRepo  # noqa: E402
from tracebed.stores.pg.pool import create_pool, scoped  # noqa: E402
from tracebed.workers.invalidator import (  # noqa: E402
    LifecycleMemoryRow,
    LifecycleTransitionWrite,
    MemoryLifecycleRepoPort,
)

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)

# The raw seed INSERT is test-local SQL (scripts/raw_sql_lint.py only guards src/); a test must be
# able to place a row in an exact status with an exact provenance/timestamp shape.
_SEED_SQL = """
INSERT INTO memory_item (
    id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier,
    status, content, content_hash, token_count, provenance, scan_verdict_id,
    strike_count, q_value, status_changed_at, last_retrieved_at, created_at, last_revalidated_at
) VALUES (
    %(id)s, %(project_id)s, 'project_shared', NULL, %(mem_type)s, 'k', 'operational', 'B',
    %(status)s, 'c', 'h', 1, %(provenance)s, %(scan_verdict_id)s,
    %(strike_count)s, %(q_value)s, %(status_changed_at)s, %(last_retrieved_at)s,
    %(created_at)s, %(last_revalidated_at)s
)
"""

_READ_RAW_SQL = """
SELECT status, status_changed_at, strike_count, q_value, last_revalidated_at, last_retrieved_at
FROM memory_item WHERE project_id = %(project_id)s AND id = %(id)s
"""


# --------------------------------------------------------------------------- #
# Scratch-DB fixture: one private database for the whole module.
# --------------------------------------------------------------------------- #


@dataclass
class _Env:
    dsn: str
    owner_pool: object
    app_pool: object
    project_a: ProjectId
    project_b: ProjectId


@pytest.fixture(scope="module")
def env() -> Iterator[_Env]:
    import os

    owner_dsn = os.environ.get("TB_STORAGE__PG_DSN")
    if not owner_dsn:
        pytest.skip("TB_STORAGE__PG_DSN is not set — no Postgres available")

    db_name = f"tb_memlifecycle_{uuid.uuid4().hex[:12]}"
    try:
        admin = psycopg.connect(owner_dsn, autocommit=True, connect_timeout=2)
    except Exception as exc:  # pragma: no cover - environment probe
        pytest.skip(f"Postgres unreachable (TB_STORAGE__PG_DSN): {exc}")

    with admin:
        admin.execute(f'CREATE DATABASE "{db_name}"')
        # From here on the database EXISTS: any setup failure below must still drop it, so the
        # whole body is wrapped so a leaked scratch DB can never outlive a failed run.
        owner_pool = None
        app_pool = None
        try:
            # apply_migrations() -> yoyo needs a URL-scheme DSN, not make_conninfo's kv format, so
            # the scratch DSN is derived by swapping the database name in the owner URL's path.
            from urllib.parse import urlsplit, urlunsplit

            scratch_dsn = urlunsplit(urlsplit(owner_dsn)._replace(path=f"/{db_name}"))

            from tracebed.stores.pg.migrate import apply_migrations
            from tracebed.stores.pg.partitions import create_project_partitions

            apply_migrations(scratch_dsn)

            project_a = ProjectId(uuid.uuid4())
            project_b = ProjectId(uuid.uuid4())
            owner_pool = create_pool(scratch_dsn)
            with owner_pool.connection() as conn:
                create_project_partitions(conn, project_a)
                create_project_partitions(conn, project_b)

            app_dsn = make_conninfo(scratch_dsn, user="tracebed_app", password="tracebed_app_dev")
            app_pool = create_pool(app_dsn)

            yield _Env(scratch_dsn, owner_pool, app_pool, project_a, project_b)
        finally:
            if owner_pool is not None:
                owner_pool.close()
            if app_pool is not None:
                app_pool.close()
            # WITH (FORCE) terminates any lingering backend so the DROP cannot wedge on a
            # leaked connection (PostgreSQL 13+; the container is 18.3).
            admin.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')


@pytest.fixture(autouse=True)
def _clean(env: _Env) -> None:
    """One database is shared across the module (migrations + partitions are expensive); clear
    both projects' `memory_item` rows before each test so a `select_by_status` in one test never
    sees another test's seeded rows. DELETE through `scoped()` so the owner's FORCE-RLS predicate
    is satisfied per project."""
    for p in (env.project_a, env.project_b):
        with scoped(env.owner_pool, p) as conn:  # type: ignore[arg-type]
            conn.execute("DELETE FROM memory_item WHERE project_id = %(p)s", {"p": p})


# --------------------------------------------------------------------------- #
# Seeding + raw read helpers.
# --------------------------------------------------------------------------- #


def _provenance(
    *,
    tool_refs: tuple[str, ...] = (),
    trace_ids: tuple[RunId, ...] = (),
    input_sig_hashes: tuple[bytes, ...] = (),
) -> Provenance:
    # DISTILLER requires a trace_id (invariant 6); default one when the test does not pin trace_ids.
    return Provenance(
        cls=ProvenanceClass.DISTILLER,
        trace_ids=trace_ids or (RunId(uuid.uuid4()),),
        tool_refs=tool_refs,
        input_sig_hashes=input_sig_hashes,
    )


def _mid(tag: int) -> MemoryId:
    return MemoryId(uuid.UUID(int=tag))


def _seed(
    env: _Env,
    project_id: ProjectId,
    *,
    mem_id: MemoryId,
    status: Status,
    provenance: Provenance | None = None,
    status_changed_at: datetime | None = EPOCH,
    last_retrieved_at: datetime | None = None,
    created_at: datetime = EPOCH,
    strike_count: int = 0,
    q_value: float = 0.5,
    last_revalidated_at: datetime | None = None,
) -> LifecycleMemoryRow:
    """Insert one `memory_item` row and return the equivalent `LifecycleMemoryRow` (the reference
    vault's view of the same row). Seeds through `scoped()` so the owner (subject to FORCE RLS)
    passes the isolation policy on INSERT."""
    prov = provenance if provenance is not None else _provenance()
    params = {
        "id": mem_id,
        "project_id": project_id,
        "mem_type": MemType.LESSON.value,
        "status": status.value,
        "provenance": Json(prov.to_json()),
        "scan_verdict_id": uuid.uuid4(),
        "strike_count": strike_count,
        "q_value": q_value,
        "status_changed_at": status_changed_at,
        "last_retrieved_at": last_retrieved_at,
        "created_at": created_at,
        "last_revalidated_at": last_revalidated_at,
    }
    with scoped(env.owner_pool, project_id) as conn:  # type: ignore[arg-type]
        conn.execute(_SEED_SQL, params)
    return LifecycleMemoryRow(
        id=mem_id,
        project_id=project_id,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=prov,
        status_changed_at=status_changed_at,
        strike_count=strike_count,
        last_retrieved_at=last_retrieved_at,
        created_at=created_at,
        q_value=q_value,
    )


def _read_raw(env: _Env, project_id: ProjectId, mem_id: MemoryId) -> dict[str, object]:
    with scoped(env.owner_pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[arg-type]
        cur.execute(_READ_RAW_SQL, {"project_id": project_id, "id": mem_id})
        row = cur.fetchone()
    assert row is not None
    return row


# --------------------------------------------------------------------------- #
# Reference vault: the UNION of the three worker `_FakeRepo`s' observable contracts.
# --------------------------------------------------------------------------- #


class _ReferenceVault:
    """In-memory oracle encoding the combined contract of all three fakes.

    persist union: status = to_status; status_changed_at = now IFF from != to (else old);
    strike_count = write.strike_count when not None (else old); q_value = write.q_value when not
    None (else old). `last_revalidated_at` is write-only (not carried on `LifecycleMemoryRow`), so
    it is not part of the row projection either fake or store reads back — it is verified against
    the raw column separately.
    """

    def __init__(self, rows: Sequence[LifecycleMemoryRow]) -> None:
        self._rows: dict[MemoryId, LifecycleMemoryRow] = {r.id: r for r in rows}

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> list[LifecycleMemoryRow]:
        tool_set, trace_set, hash_set = set(tool_refs), set(trace_ids), set(input_sig_hashes)
        out = [
            r
            for r in self._rows.values()
            if r.project_id == project_id
            and (
                tool_set & set(r.provenance.tool_refs)
                or trace_set & set(r.provenance.trace_ids)
                or hash_set & set(r.provenance.input_sig_hashes)
            )
        ]
        return sorted(out, key=lambda r: r.id.value)

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> list[LifecycleMemoryRow]:
        out = [
            r
            for r in self._rows.values()
            if r.project_id == project_id and r.status in statuses
        ]
        return sorted(out, key=lambda r: r.id.value)[:limit]

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> list[LifecycleMemoryRow]:
        out = []
        for r in self._rows.values():
            if r.project_id != project_id or r.status is not Status.VALIDATED:
                continue
            reference = r.last_retrieved_at if r.last_retrieved_at is not None else r.created_at
            if reference <= older_than:
                out.append(r)
        return sorted(out, key=lambda r: r.id.value)[:limit]

    def persist(self, project_id: ProjectId, write: LifecycleTransitionWrite) -> None:
        old = self._rows[write.memory_id]
        self._rows[write.memory_id] = replace(
            old,
            status=write.to_status,
            status_changed_at=(
                write.now if write.from_status != write.to_status else old.status_changed_at
            ),
            strike_count=write.strike_count if write.strike_count is not None else old.strike_count,
            q_value=write.q_value if write.q_value is not None else old.q_value,
        )


# --------------------------------------------------------------------------- #
# (a) Fake-parity.
# --------------------------------------------------------------------------- #


def test_store_satisfies_the_runtime_checkable_protocol(env: _Env) -> None:
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    assert isinstance(store, MemoryLifecycleRepoPort)


def test_select_by_provenance_union_round_trips_runid_and_hex_hash(env: _Env) -> None:
    """The jsonb `?|` UNION over the three selector fields, with the exact on-disk encodings a
    RunId and a `bytes` input signature hash serialise to (str(RunId), lowercase hex)."""
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a

    trace = RunId(uuid.uuid4())
    sig = b"\x0a\xff\x01"
    by_tool = _seed(env, p, mem_id=_mid(0x101), status=Status.VALIDATED,
                    provenance=_provenance(tool_refs=("tool-x",)))
    by_trace = _seed(env, p, mem_id=_mid(0x102), status=Status.CANDIDATE,
                     provenance=_provenance(trace_ids=(trace,)))
    by_hash = _seed(env, p, mem_id=_mid(0x103), status=Status.VALIDATED,
                    provenance=_provenance(input_sig_hashes=(sig,)))
    unrelated = _seed(env, p, mem_id=_mid(0x104), status=Status.VALIDATED,
                      provenance=_provenance(tool_refs=("tool-y",)))

    ref = _ReferenceVault([by_tool, by_trace, by_hash, unrelated])
    kwargs: dict[str, object] = {
        "tool_refs": ("tool-x",),
        "trace_ids": (trace,),
        "input_sig_hashes": (sig,),
    }
    got = store.select_by_provenance(p, **kwargs)  # type: ignore[arg-type]
    want = ref.select_by_provenance(p, **kwargs)  # type: ignore[arg-type]

    assert list(got) == want
    assert {r.id for r in got} == {by_tool.id, by_trace.id, by_hash.id}
    assert unrelated.id not in {r.id for r in got}
    # The hex hash and the RunId genuinely round-tripped through jsonb, back into typed values.
    hash_row = next(r for r in got if r.id == by_hash.id)
    assert sig in hash_row.provenance.input_sig_hashes
    trace_row = next(r for r in got if r.id == by_trace.id)
    assert trace in trace_row.provenance.trace_ids


def test_select_by_provenance_empty_selector_matches_nothing(env: _Env) -> None:
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a
    _seed(env, p, mem_id=_mid(0x111), status=Status.VALIDATED,
          provenance=_provenance(tool_refs=("tool-z",)))
    assert list(store.select_by_provenance(p)) == []


def test_select_by_status_matches_reference_and_orders_by_id(env: _Env) -> None:
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a
    v1 = _seed(env, p, mem_id=_mid(0x201), status=Status.QUARANTINED)
    v2 = _seed(env, p, mem_id=_mid(0x202), status=Status.QUARANTINED)
    other = _seed(env, p, mem_id=_mid(0x203), status=Status.CANDIDATE)
    ref = _ReferenceVault([v1, v2, other])

    got = store.select_by_status(p, [Status.QUARANTINED])
    assert list(got) == ref.select_by_status(p, [Status.QUARANTINED])
    assert [r.id for r in got] == [v1.id, v2.id]

    # Empty status list issues no query and returns nothing (parity with list_memories' fix).
    assert list(store.select_by_status(p, [])) == []


def test_select_due_for_revalidation_inclusive_boundary_validated_only(env: _Env) -> None:
    """Inclusive `<=` on COALESCE(last_retrieved_at, created_at), VALIDATED only."""
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a
    older = EPOCH + timedelta(days=30)

    # last_retrieved_at exactly at the boundary -> due (inclusive).
    at_boundary = _seed(env, p, mem_id=_mid(0x301), status=Status.VALIDATED,
                        last_retrieved_at=older, created_at=EPOCH)
    # one second past the boundary -> not due.
    just_after = _seed(env, p, mem_id=_mid(0x302), status=Status.VALIDATED,
                       last_retrieved_at=older + timedelta(seconds=1), created_at=EPOCH)
    # never retrieved -> falls back to created_at, which is well before the boundary -> due.
    never = _seed(env, p, mem_id=_mid(0x303), status=Status.VALIDATED,
                  last_retrieved_at=None, created_at=EPOCH)
    # a STALE row idle enough is still excluded — VALIDATED only.
    stale = _seed(env, p, mem_id=_mid(0x304), status=Status.STALE,
                  last_retrieved_at=None, created_at=EPOCH)

    ref = _ReferenceVault([at_boundary, just_after, never, stale])
    got = store.select_due_for_revalidation(p, older_than=older)
    assert list(got) == ref.select_due_for_revalidation(p, older_than=older)
    assert {r.id for r in got} == {at_boundary.id, never.id}
    assert just_after.id not in {r.id for r in got}
    assert stale.id not in {r.id for r in got}


def test_persist_real_transition_sets_status_changed_at_and_conditional_fields(env: _Env) -> None:
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a
    row = _seed(env, p, mem_id=_mid(0x401), status=Status.VALIDATED,
                status_changed_at=EPOCH, strike_count=0, q_value=0.5)
    ref = _ReferenceVault([row])

    now = EPOCH + timedelta(days=5)
    write = LifecycleTransitionWrite(
        memory_id=row.id, from_status=Status.VALIDATED, to_status=Status.STALE, now=now,
        strike_count=1, last_revalidated_at=now,
    )
    store.persist(p, write)
    ref.persist(p, write)

    got = list(store.select_by_status(p, [Status.STALE]))
    assert got == ref.select_by_status(p, [Status.STALE])
    (moved,) = got
    assert moved.status is Status.STALE
    assert moved.status_changed_at == now  # a REAL transition moved it
    assert moved.strike_count == 1  # conditional strike_count written
    assert moved.q_value == 0.5  # q_value was None on the write -> left untouched
    # last_revalidated_at is write-only; verify it landed on the raw column.
    raw = _read_raw(env, p, row.id)
    assert raw["last_revalidated_at"] == now


def test_persist_field_touch_leaves_status_changed_at_untouched(env: _Env) -> None:
    """The load-bearing from==to rule: a decay/reval touch that bumped status_changed_at would
    corrupt every subsequent TTL/idle computation."""
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a
    original_changed = EPOCH
    row = _seed(env, p, mem_id=_mid(0x501), status=Status.VALIDATED,
                status_changed_at=original_changed, strike_count=2, q_value=0.5)
    ref = _ReferenceVault([row])

    now = EPOCH + timedelta(days=9)
    # decay-style field touch: from == to, only q_value moves.
    write = LifecycleTransitionWrite(
        memory_id=row.id, from_status=Status.VALIDATED, to_status=Status.VALIDATED, now=now,
        q_value=0.4825,
    )
    store.persist(p, write)
    ref.persist(p, write)

    got = list(store.select_by_status(p, [Status.VALIDATED]))
    assert got == ref.select_by_status(p, [Status.VALIDATED])
    (touched,) = got
    assert touched.status is Status.VALIDATED
    assert touched.status_changed_at == original_changed  # NOT moved to `now`
    assert touched.q_value == pytest.approx(0.4825)  # q_value conditionally written
    assert touched.strike_count == 2  # strike_count None on the write -> untouched


def test_persist_reval_pass_touch_writes_only_last_revalidated_at(env: _Env) -> None:
    """RevalidationWorker.check_validated's passing branch: from==to==VALIDATED, only
    last_revalidated_at is carried; status_changed_at, strike_count, q_value all stay put."""
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a
    row = _seed(env, p, mem_id=_mid(0x601), status=Status.VALIDATED,
                status_changed_at=EPOCH, strike_count=3, q_value=0.77)
    now = EPOCH + timedelta(days=40)
    store.persist(p, LifecycleTransitionWrite(
        memory_id=row.id, from_status=Status.VALIDATED, to_status=Status.VALIDATED, now=now,
        last_revalidated_at=now,
    ))
    raw = _read_raw(env, p, row.id)
    assert raw["status"] == Status.VALIDATED.value
    assert raw["status_changed_at"] == EPOCH
    assert raw["strike_count"] == 3
    assert raw["q_value"] == pytest.approx(0.77)
    assert raw["last_revalidated_at"] == now


def test_persist_stale_transition_matches_optimistic_concurrency_on_wrong_from(env: _Env) -> None:
    """A persist whose from_status no longer matches the row raises StaleStatusTransition and
    mutates nothing — the same optimistic-concurrency guard LifecycleWriter uses."""
    store = MemoryLifecycleRepo(env.owner_pool)  # type: ignore[arg-type]
    p = env.project_a
    row = _seed(env, p, mem_id=_mid(0x701), status=Status.VALIDATED, status_changed_at=EPOCH)
    with pytest.raises(StaleStatusTransition):
        store.persist(p, LifecycleTransitionWrite(
            memory_id=row.id, from_status=Status.STALE, to_status=Status.RETIRED,
            now=EPOCH + timedelta(days=1),
        ))
    raw = _read_raw(env, p, row.id)
    assert raw["status"] == Status.VALIDATED.value  # unchanged
    assert raw["status_changed_at"] == EPOCH


# --------------------------------------------------------------------------- #
# (b) Cross-project denial under `tracebed_app` (NOBYPASSRLS).
# --------------------------------------------------------------------------- #


def test_app_role_scoped_to_b_cannot_read_or_write_project_a(env: _Env) -> None:
    a, b = env.project_a, env.project_b
    trace = RunId(uuid.uuid4())
    sig = b"\x01\x02\x03"
    a_row = _seed(env, a, mem_id=_mid(0x801), status=Status.VALIDATED,
                  provenance=_provenance(tool_refs=("tool-secret",), trace_ids=(trace,),
                                         input_sig_hashes=(sig,)),
                  status_changed_at=EPOCH, last_retrieved_at=None, created_at=EPOCH)

    # The store the isolation bar is measured through: the app role, NOBYPASSRLS.
    app_store = MemoryLifecycleRepo(env.app_pool)  # type: ignore[arg-type]

    # Every read, scoped to B, is blind to A's row.
    assert list(app_store.select_by_provenance(
        b, tool_refs=("tool-secret",), trace_ids=(trace,), input_sig_hashes=(sig,))) == []
    assert list(app_store.select_by_status(b, [Status.VALIDATED])) == []
    assert list(app_store.select_due_for_revalidation(
        b, older_than=EPOCH + timedelta(days=3650))) == []

    # A write, scoped to B, targeting A's id mutates nothing: the WHERE matches zero rows in B's
    # partition -> StaleStatusTransition, and A's row is left exactly as seeded.
    with pytest.raises(StaleStatusTransition):
        app_store.persist(b, LifecycleTransitionWrite(
            memory_id=a_row.id, from_status=Status.VALIDATED, to_status=Status.STALE,
            now=EPOCH + timedelta(days=1), strike_count=1,
        ))
    raw = _read_raw(env, a, a_row.id)  # owner read of A's real row
    assert raw["status"] == Status.VALIDATED.value
    assert raw["status_changed_at"] == EPOCH
    assert raw["strike_count"] == 0


def test_app_role_scoped_to_a_does_see_a_row_guarding_the_guard(env: _Env) -> None:
    """The denial above must be about the project, not a blanket failure: the same app-role store,
    scoped to A, reads and writes A's own row normally."""
    a = env.project_a
    row = _seed(env, a, mem_id=_mid(0x901), status=Status.QUARANTINED, status_changed_at=EPOCH)
    app_store = MemoryLifecycleRepo(env.app_pool)  # type: ignore[arg-type]

    got = list(app_store.select_by_status(a, [Status.QUARANTINED]))
    assert row.id in {r.id for r in got}

    now = EPOCH + timedelta(days=30)
    app_store.persist(a, LifecycleTransitionWrite(
        memory_id=row.id, from_status=Status.QUARANTINED, to_status=Status.ARCHIVED, now=now,
    ))
    raw = _read_raw(env, a, row.id)
    assert raw["status"] == Status.ARCHIVED.value
    assert raw["status_changed_at"] == now
