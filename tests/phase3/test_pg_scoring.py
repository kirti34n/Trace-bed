"""`stores.pg.scoring.ScorerRepo` — `workers.scorer.ScorerRepoPort` over Postgres
(docs/FIDELITY-AUDIT.md M3; PLAN.md §11 M3).

Two mandatory classes, both against a real Postgres in a throwaway database provisioned by
the scratch-DB recipe (CREATE DATABASE -> apply_migrations -> create_project_partitions for
two projects A and B -> provision the memory_q_update partition -> ... -> DROP DATABASE):

  * `TestFakeParity` drives the SAME call sequence through the PG store and the worker's
    in-memory `FakeScorerRepo`, via `run_scorer_batch`, and asserts identical observable
    results — plus the store-specific acceptance points (replay idempotency ACROSS calendar
    days, per-UTC-day cap bucketing, and `apply_q_update`'s atomic ON-CONFLICT replay guard
    under two concurrent ticks).
  * `TestCrossProjectDenial` opens a second pool as `tracebed_app` (NOBYPASSRLS — the owner
    would hide a missing predicate) scoped to project B and proves it can neither READ nor
    WRITE project A's Q through this store.

`memory_q_update` has no per-project partition until the integration pass adds it to
`stores/pg/ddl.py`'s `PARTITIONED_TABLES` (out of this chunk's file list), so the fixture
provisions that partition directly, mirroring exactly what the ddl.py registration will emit
(CREATE PARTITION OF + ENABLE/FORCE RLS + the isolation policy + the (project_id, memory_id,
scored_at) index + the tracebed_app grant).
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.conninfo import make_conninfo
from psycopg_pool import ConnectionPool

# The canonical fakes — the acceptance fake the worker was validated against.
from tests.phase3.test_scorer_q_update import FakeJudge, FakeScorerRepo
from tracebed.domain.config import ScoringConfig
from tracebed.domain.enums import AdapterClass
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import (
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    mint_memory_id,
    mint_run_id,
)
from tracebed.stores.pg.migrate import apply_migrations
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.stores.pg.scoring import ScorerRepo
from tracebed.workers.epochs import ScoringEpoch
from tracebed.workers.scorer import (
    QUpdate,
    ScoreBatchResult,
    ScorerRepoPort,
    ScoringEvent,
    run_scorer_batch,
)

pytestmark = [pytest.mark.phase3, pytest.mark.integration]

_ISOLATION_PREDICATE = (
    "project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid"
)

_NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
_CONFIG = ScoringConfig()  # alpha=0.3, default adapter_weights, cap=1/day
_EPOCH = ScoringEpoch(
    epoch_id=1,
    judge_model_id="gemini-3.1-pro",
    judge_model_version="001",
    sampling_params={"temperature": 0.0, "max_tokens": 8},
    prompt_hash="a" * 64,
    started_at=_NOW,
)


# --------------------------------------------------------------------------------------- #
# Scratch-DB provisioning.
# --------------------------------------------------------------------------------------- #


@dataclass
class _Scratch:
    owner_url: str
    owner_pool: ConnectionPool
    app_conninfo: str
    project_a: ProjectId
    project_b: ProjectId


def _provision_q_update_partition(conn: psycopg.Connection[object], project_id: ProjectId) -> None:
    """Exactly what the deferred `stores/pg/ddl.py` registration for `memory_q_update` will
    emit for one project's partition: CREATE PARTITION OF, ENABLE + FORCE RLS, the isolation
    policy, the (project_id, memory_id, scored_at) index, and the tracebed_app grant."""
    name = f"memory_q_update_p_{project_id.value.hex}"
    policy = f"{name}_isolation"
    bound = f"'{project_id.value}'"
    conn.execute(f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF memory_q_update FOR VALUES IN ({bound})")
    conn.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    conn.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
    conn.execute(f"DROP POLICY IF EXISTS {policy} ON {name}")
    conn.execute(f"CREATE POLICY {policy} ON {name} USING ({_ISOLATION_PREDICATE})")
    conn.execute(f"CREATE INDEX IF NOT EXISTS {name}_scored ON {name} (project_id, memory_id, scored_at)")
    conn.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO tracebed_app")


@pytest.fixture
def scratch(pg: str) -> Iterator[_Scratch]:
    """A unique throwaway database, migrated, with two fully provisioned projects. Dropped on
    teardown regardless of outcome. Isolated from the shared tracebed DB and from sibling
    agents by its random name."""
    db_name = f"tb_scoring_{uuid.uuid4().hex}"
    base = pg.rsplit("/", 1)[0]
    owner_url = f"{base}/{db_name}"

    admin = psycopg.connect(pg, autocommit=True)
    try:
        admin.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        admin.close()

    try:
        apply_migrations(owner_url)
        project_a = ProjectId(uuid4())
        project_b = ProjectId(uuid4())
        with psycopg.connect(owner_url) as conn:
            for pid in (project_a, project_b):
                create_project_partitions(conn, pid)
            conn.commit()
            with conn.transaction():
                for pid in (project_a, project_b):
                    _provision_q_update_partition(conn, pid)

        owner_pool = create_pool(owner_url)
        app_conninfo = make_conninfo(owner_url, user="tracebed_app", password="tracebed_app_dev")
        try:
            yield _Scratch(
                owner_url=owner_url,
                owner_pool=owner_pool,
                app_conninfo=app_conninfo,
                project_a=project_a,
                project_b=project_b,
            )
        finally:
            owner_pool.close()
    finally:
        drop = psycopg.connect(pg, autocommit=True)
        try:
            drop.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (db_name,),
            )
            drop.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            drop.close()


# --------------------------------------------------------------------------------------- #
# Seeding + event helpers.
# --------------------------------------------------------------------------------------- #

_SEED_MEMORY_SQL = """
INSERT INTO memory_item (
    id, project_id, scope_type, mem_type, kind, lane, trust_tier, status,
    content, content_hash, token_count, provenance, scan_verdict_id
) VALUES (
    %(id)s, %(project_id)s, 'project_shared', 'lesson', 'k', 'operational', 'A', 'validated',
    'c', 'h', 0, '{}'::jsonb, %(verdict)s
)
"""


def _seed_memory(pool: ConnectionPool, project_id: ProjectId, memory_id: MemoryId) -> None:
    with scoped(pool, project_id) as conn:
        conn.execute(
            _SEED_MEMORY_SQL,
            {"id": memory_id, "project_id": project_id, "verdict": uuid4()},
        )


def _event(
    *,
    memory_id: MemoryId,
    adapter: AdapterClass = AdapterClass.VERDICT,
    r: float = 1.0,
    arrived_at: datetime = _NOW,
    event_id: UUID | None = None,
    run_id: RunId | None = None,
    principal_id: PrincipalId | None = None,
    outcome_summary: str = "the run succeeded",
) -> ScoringEvent:
    return ScoringEvent(
        event_id=event_id or uuid4(),
        run_id=run_id or mint_run_id(),
        memory_id=memory_id,
        adapter=adapter,
        r=r,
        principal_id=principal_id or PrincipalId(uuid4()),
        arrived_at=arrived_at,
        outcome_summary=outcome_summary,
    )


class _StepClock:
    """Returns each supplied instant in turn (last one repeats). Lets a single tick pin its
    UTC day while a later tick advances a day, without a global clock."""

    def __init__(self, instants: Sequence[datetime]) -> None:
        self._instants = list(instants)
        self.reads = 0

    def now(self) -> datetime:
        instant = self._instants[min(self.reads, len(self._instants) - 1)]
        self.reads += 1
        return instant

    def now_ms(self) -> int:
        return int(self.now().timestamp() * 1000)

    def monotonic_ms(self) -> float:
        return float(self.reads)


def _result_tuple(r: ScoreBatchResult) -> tuple[object, ...]:
    """The observable partition of a batch result, id-only, for equality across two backends."""
    return (
        tuple(u.event_id for u in r.applied),
        tuple(sorted(r.skipped_replay, key=lambda e: e.bytes)),
        tuple(sorted(r.skipped_short_circuit, key=lambda e: e.bytes)),
        tuple(sorted(r.skipped_cap, key=lambda e: e.bytes)),
    )


# --------------------------------------------------------------------------------------- #
# (a) Fake-parity.
# --------------------------------------------------------------------------------------- #


class TestFakeParity:
    def test_scorer_repo_satisfies_the_port(self, scratch: _Scratch) -> None:
        assert isinstance(ScorerRepo(scratch.owner_pool), ScorerRepoPort)

    def test_reads_match_the_fake_on_a_fresh_memory(self, scratch: _Scratch) -> None:
        pid = scratch.project_a
        mid = mint_memory_id()
        _seed_memory(scratch.owner_pool, pid, mid)
        store = ScorerRepo(scratch.owner_pool)
        fake = FakeScorerRepo(project_id=pid, memory_id=mid, initial_q=0.5)

        assert store.current_q(pid, mid) == fake.current_q(pid, mid) == 0.5
        assert store.applied_event_ids(pid, mid) == fake.applied_event_ids(pid, mid) == set()
        assert (
            store.scored_updates_today(pid, mid, _NOW.date())
            == fake.scored_updates_today(pid, mid, _NOW.date())
            == 0
        )

    def _run_both(
        self,
        scratch: _Scratch,
        *,
        candidates_by_tick: Sequence[Sequence[ScoringEvent]],
        instants: Sequence[datetime],
    ) -> tuple[list[ScoreBatchResult], list[ScoreBatchResult], ScorerRepo, FakeScorerRepo, MemoryId]:
        """Drive the identical tick sequence through the PG store and the fake, each on its own
        fresh memory, and return both result streams plus the two repos for state comparison."""
        pid = scratch.project_a
        store_mid = mint_memory_id()
        fake_mid = mint_memory_id()
        _seed_memory(scratch.owner_pool, pid, store_mid)
        store = ScorerRepo(scratch.owner_pool)
        fake = FakeScorerRepo(project_id=pid, memory_id=fake_mid, initial_q=0.5)

        store_results: list[ScoreBatchResult] = []
        fake_results: list[ScoreBatchResult] = []
        for tick, ticks_candidates in enumerate(candidates_by_tick):
            store_clock = _StepClock([instants[tick]])
            fake_clock = _StepClock([instants[tick]])
            store_results.append(
                run_scorer_batch(
                    project_id=pid,
                    memory_id=store_mid,
                    memory_content="m",
                    candidates=[_rebind(e, store_mid) for e in ticks_candidates],
                    repo=store,
                    judge=FakeJudge(factor=1.0),
                    config=_CONFIG,
                    epoch=_EPOCH,
                    clock=store_clock,
                )
            )
            fake_results.append(
                run_scorer_batch(
                    project_id=pid,
                    memory_id=fake_mid,
                    memory_content="m",
                    candidates=[_rebind(e, fake_mid) for e in ticks_candidates],
                    repo=fake,
                    judge=FakeJudge(factor=1.0),
                    config=_CONFIG,
                    epoch=_EPOCH,
                    clock=fake_clock,
                )
            )
        return store_results, fake_results, store, fake, store_mid

    def test_apply_then_replay_then_cap_matches_the_fake(self, scratch: _Scratch) -> None:
        e1 = _event(memory_id=mint_memory_id(), event_id=uuid4())
        e2 = _event(memory_id=mint_memory_id(), event_id=uuid4(), arrived_at=_NOW + timedelta(hours=1))
        # tick 0: e1 fresh -> applied. tick 1 (same day): e1 replay + e2 fresh -> e1
        # skipped_replay, e2 skipped_cap (slot already spent today).
        store_r, fake_r, store, fake, mid = self._run_both(
            scratch,
            candidates_by_tick=[[e1], [e1, e2]],
            instants=[_NOW, _NOW + timedelta(hours=2)],
        )
        assert [_result_tuple(r) for r in store_r] == [_result_tuple(r) for r in fake_r]
        # Observable state agrees method-for-method.
        pid = scratch.project_a
        assert store.current_q(pid, mid) == pytest.approx(fake.current_q(pid, fake._memory_id))
        assert store.current_q(pid, mid) == pytest.approx(0.65)
        assert store.applied_event_ids(pid, mid) == {e1.event_id}
        assert store.scored_updates_today(pid, mid, _NOW.date()) == 1

    def test_replay_across_calendar_days_does_not_move_q_twice(self, scratch: _Scratch) -> None:
        """Not day-scoped: an event first applied on day D, replayed on D+1, must stay on the
        ledger and never move Q again — and a genuinely fresh D+1 event still scores."""
        e = _event(memory_id=mint_memory_id(), event_id=uuid4())
        f = _event(memory_id=mint_memory_id(), event_id=uuid4(), arrived_at=_NOW + timedelta(days=1))
        day2 = _NOW + timedelta(days=1)
        store_r, fake_r, store, _fake, mid = self._run_both(
            scratch,
            candidates_by_tick=[[e], [e, f]],
            instants=[_NOW, day2],
        )
        assert [_result_tuple(r) for r in store_r] == [_result_tuple(r) for r in fake_r]
        pid = scratch.project_a
        # e applied day 1, f applied day 2; e replayed on day 2 moved nothing.
        assert store.applied_event_ids(pid, mid) == {e.event_id, f.event_id}
        assert store.scored_updates_today(pid, mid, _NOW.date()) == 1
        assert store.scored_updates_today(pid, mid, day2.date()) == 1
        assert store_r[1].skipped_replay == (e.event_id,)
        assert store_r[1].applied[0].event_id == f.event_id

    def test_scored_updates_today_buckets_on_the_utc_date(self, scratch: _Scratch) -> None:
        """A stamp late on day D and one early on day D+1 (UTC) land in different buckets even
        though only ~a second apart — the bucketing is UTC-calendar, not a rolling 24h."""
        pid = scratch.project_a
        mid = mint_memory_id()
        _seed_memory(scratch.owner_pool, pid, mid)
        store = ScorerRepo(scratch.owner_pool)
        late = datetime(2026, 7, 26, 23, 59, 59, tzinfo=UTC)
        early = datetime(2026, 7, 27, 0, 0, 1, tzinfo=UTC)
        store.apply_q_update(pid, _q(mid, scored_at=late))
        store.apply_q_update(pid, _q(mid, scored_at=early))
        assert store.scored_updates_today(pid, mid, date(2026, 7, 26)) == 1
        assert store.scored_updates_today(pid, mid, date(2026, 7, 27)) == 1

    def test_apply_q_update_is_replay_idempotent_on_the_same_event(self, scratch: _Scratch) -> None:
        """The ON CONFLICT (project_id, memory_id, event_id) DO NOTHING guard: applying the same
        event twice writes the ledger row once and moves Q once — the store's own guarantee,
        independent of the worker's pre-filtering."""
        pid = scratch.project_a
        mid = mint_memory_id()
        _seed_memory(scratch.owner_pool, pid, mid)
        store = ScorerRepo(scratch.owner_pool)
        update = _q(mid, scored_at=_NOW, new_q=0.7)
        store.apply_q_update(pid, update)
        store.apply_q_update(pid, update)  # replay
        assert store.current_q(pid, mid) == pytest.approx(0.7)
        assert store.scored_updates_today(pid, mid, _NOW.date()) == 1
        assert _scored_use_count(scratch.owner_pool, pid, mid) == 1

    def test_two_concurrent_ticks_produce_exactly_one_write(self, scratch: _Scratch) -> None:
        """SELECT ... FOR UPDATE serialises the two apply transactions and the ON CONFLICT guard
        makes the loser a no-op: two concurrent ticks racing the same redelivered event → exactly
        one ledger row, one scored use, Q moved once (module docstring, atomicity)."""
        pid = scratch.project_a
        mid = mint_memory_id()
        _seed_memory(scratch.owner_pool, pid, mid)
        pool = create_pool(scratch.owner_url, min_size=2, max_size=4)
        try:
            store = ScorerRepo(pool)
            update = _q(mid, scored_at=_NOW, new_q=0.72)
            barrier = threading.Barrier(2)

            def _apply() -> None:
                barrier.wait()
                store.apply_q_update(pid, update)

            with ThreadPoolExecutor(max_workers=2) as pool_exec:
                futures = [pool_exec.submit(_apply) for _ in range(2)]
                for fut in futures:
                    fut.result()

            assert store.current_q(pid, mid) == pytest.approx(0.72)
            assert store.scored_updates_today(pid, mid, _NOW.date()) == 1
            assert _scored_use_count(pool, pid, mid) == 1
        finally:
            pool.close()

    def test_apply_persists_epoch_and_principal_and_previous_q(self, scratch: _Scratch) -> None:
        """The additive durability columns the fakes could not express: epoch_id (invariant 7),
        principal_id (D-021's distinct-principal floor), previous_q/contribution (auditability)."""
        pid = scratch.project_a
        mid = mint_memory_id()
        _seed_memory(scratch.owner_pool, pid, mid)
        store = ScorerRepo(scratch.owner_pool)
        principal = PrincipalId(uuid4())
        event_id = uuid4()
        update = QUpdate(
            memory_id=mid,
            event_id=event_id,
            principal_id=principal,
            previous_q=0.5,
            new_q=0.61,
            contribution=0.5,
            epoch_id=7,
            scored_at=_NOW,
        )
        store.apply_q_update(pid, update)
        with scoped(scratch.owner_pool, pid) as conn:
            row = conn.execute(
                "SELECT principal_id, previous_q, new_q, contribution, epoch_id "
                "FROM memory_q_update WHERE project_id = %(p)s AND memory_id = %(m)s "
                "AND event_id = %(e)s",
                {"p": pid, "m": mid, "e": event_id},
            ).fetchone()
            item = conn.execute(
                "SELECT epoch_id, last_scored_at FROM memory_item "
                "WHERE project_id = %(p)s AND id = %(m)s",
                {"p": pid, "m": mid},
            ).fetchone()
        assert row is not None
        assert PrincipalId(row[0]) == principal
        assert row[1] == pytest.approx(0.5)
        assert row[2] == pytest.approx(0.61)
        assert row[3] == pytest.approx(0.5)
        assert row[4] == 7
        assert item is not None
        assert item[0] == 7  # memory_item.epoch_id writer (0004 deferred it here)
        assert item[1] == _NOW  # last_scored_at


# --------------------------------------------------------------------------------------- #
# (b) Cross-project denial under tracebed_app (NOBYPASSRLS).
# --------------------------------------------------------------------------------------- #


class TestCrossProjectDenial:
    def test_project_b_cannot_read_or_write_project_a_rows(self, scratch: _Scratch) -> None:
        a = scratch.project_a
        b = scratch.project_b
        mid = mint_memory_id()
        event_id = uuid4()

        # Seed A's memory and one applied Q update, via the owner store scoped to A.
        _seed_memory(scratch.owner_pool, a, mid)
        owner_store = ScorerRepo(scratch.owner_pool)
        owner_store.apply_q_update(a, _q(mid, event_id=event_id, scored_at=_NOW, new_q=0.66))
        assert owner_store.current_q(a, mid) == pytest.approx(0.66)

        # The app role: NOBYPASSRLS, so a missing predicate could not hide behind owner rights.
        app_pool = create_pool(scratch.app_conninfo)
        try:
            app_store = ScorerRepo(app_pool)

            # READS scoped to B see nothing of A's memory.
            assert app_store.applied_event_ids(b, mid) == set()
            assert app_store.scored_updates_today(b, mid, _NOW.date()) == 0
            with pytest.raises(TracebedError):  # current_q: no row visible under B's scope
                app_store.current_q(b, mid)

            # WRITE scoped to B targeting A's memory: the FOR UPDATE locks zero rows -> raise,
            # and A's ledger / Q are untouched.
            with pytest.raises(TracebedError):
                app_store.apply_q_update(b, _q(mid, event_id=uuid4(), scored_at=_NOW, new_q=0.1))
        finally:
            app_pool.close()

        # A's state is exactly as seeded — nothing B did leaked across.
        assert owner_store.current_q(a, mid) == pytest.approx(0.66)
        assert owner_store.applied_event_ids(a, mid) == {event_id}
        assert owner_store.scored_updates_today(a, mid, _NOW.date()) == 1
        assert _scored_use_count(scratch.owner_pool, a, mid) == 1


# --------------------------------------------------------------------------------------- #
# (c) Read-predicate discrimination under the OWNER pool (BYPASSRLS).
# --------------------------------------------------------------------------------------- #


class TestReadPredicateDiscriminatesUnderOwner:
    """Under the OWNER pool RLS is BYPASSED, so the explicit `project_id = %(project_id)s`
    conjunct in every read is the ONLY control confining a query to its project's partition.
    Seeding the SAME memory_id in BOTH project A and project B, with distinct Q/event payloads,
    makes each read go RED if that predicate is dropped or made constant: `id = %(memory_id)s`
    alone would then match BOTH partitions' rows. (The cross-project-denial class above cannot
    catch this — under `tracebed_app`'s RLS a missing predicate is masked.)"""

    def test_owner_scoped_reads_return_only_their_own_projects_rows(self, scratch: _Scratch) -> None:
        a, b = scratch.project_a, scratch.project_b
        mid = mint_memory_id()  # the SAME id lives in both project partitions (PK is (project_id, id))
        _seed_memory(scratch.owner_pool, a, mid)
        _seed_memory(scratch.owner_pool, b, mid)
        store = ScorerRepo(scratch.owner_pool)

        ea, eb = uuid4(), uuid4()
        store.apply_q_update(a, _q(mid, event_id=ea, scored_at=_NOW, new_q=0.61))
        store.apply_q_update(b, _q(mid, event_id=eb, scored_at=_NOW, new_q=0.42))

        # current_q: each scope reads its own partition's distinct value. Dropping the predicate
        # leaves `WHERE id = mid` matching two rows -> fetchone returns the wrong one for one scope.
        assert store.current_q(a, mid) == pytest.approx(0.61)
        assert store.current_q(b, mid) == pytest.approx(0.42)

        # applied_event_ids: exactly this project's ledger event. Without the predicate the set
        # would union both partitions' events -> {ea, eb}.
        assert store.applied_event_ids(a, mid) == {ea}
        assert store.applied_event_ids(b, mid) == {eb}

        # scored_updates_today: count within this partition only. Without the predicate the
        # count(*) spans both partitions' rows for this id and day -> 2.
        assert store.scored_updates_today(a, mid, _NOW.date()) == 1
        assert store.scored_updates_today(b, mid, _NOW.date()) == 1


# --------------------------------------------------------------------------------------- #
# (d) The per-MEMORY ledger predicate (scoring.py:86 and :98).
# --------------------------------------------------------------------------------------- #


class TestLedgerReadsAreScopedPerMemory:
    """`_APPLIED_EVENT_IDS_SQL` (scoring.py:86) and `_SCORED_UPDATES_TODAY_SQL` (scoring.py:98)
    each carry `AND memory_id = %(memory_id)s` besides the `project_id` conjunct: the ledger is
    keyed `(project_id, memory_id, event_id)`, so within ONE project two memories share a
    partition. Dropping the memory_id conjunct would make each read union EVERY memory's ledger
    rows in the project -- the replay set of one memory would carry another's applied events, and
    one memory's daily count would carry another's updates, silently defeating the per-memory
    replay guard and the per-memory daily cap.

    Every other test here seeds a single memory per project, so a dropped memory_id conjunct stays
    invisible: `project_id` alone still selects the one memory's rows. This seeds TWO distinct
    memories in the SAME project with DIFFERENT ledger payloads, so each read goes RED the moment
    the memory_id conjunct is removed. (Proven by the sibling mutation harness that monkeypatches
    each SQL constant to its conjunct-stripped form and asserts these very assertions turn red.)
    """

    def test_applied_events_and_daily_count_never_bleed_between_memories(
        self, scratch: _Scratch
    ) -> None:
        pid = scratch.project_a
        mem_a = mint_memory_id()
        mem_b = mint_memory_id()  # a SECOND memory in the SAME project/partition
        _seed_memory(scratch.owner_pool, pid, mem_a)
        _seed_memory(scratch.owner_pool, pid, mem_b)
        store = ScorerRepo(scratch.owner_pool)

        # mem_a: two distinct events applied today; mem_b: one -- distinct payloads and distinct
        # daily counts, so BOTH a dropped conjunct in _APPLIED_EVENT_IDS_SQL and one in
        # _SCORED_UPDATES_TODAY_SQL change an observed value here.
        ea1, ea2, eb = uuid4(), uuid4(), uuid4()
        store.apply_q_update(pid, _q(mem_a, event_id=ea1, scored_at=_NOW, new_q=0.61))
        store.apply_q_update(pid, _q(mem_a, event_id=ea2, scored_at=_NOW, new_q=0.62))
        store.apply_q_update(pid, _q(mem_b, event_id=eb, scored_at=_NOW, new_q=0.63))

        # applied_event_ids is per-MEMORY: mem_a's replay set is exactly its own two events, mem_b's
        # exactly its own one. Dropping the memory_id conjunct unions all three onto both -> RED.
        assert store.applied_event_ids(pid, mem_a) == {ea1, ea2}
        assert store.applied_event_ids(pid, mem_b) == {eb}

        # scored_updates_today is per-MEMORY: mem_a counted two today, mem_b one. Dropping the
        # memory_id conjunct counts all three rows for both memories -> 3 != 2 and 3 != 1 -> RED.
        assert store.scored_updates_today(pid, mem_a, _NOW.date()) == 2
        assert store.scored_updates_today(pid, mem_b, _NOW.date()) == 1

        # Sanity: the two memories really are distinct rows, each with its own scored_use_count.
        assert _scored_use_count(scratch.owner_pool, pid, mem_a) == 2
        assert _scored_use_count(scratch.owner_pool, pid, mem_b) == 1


# --------------------------------------------------------------------------------------- #
# Small helpers.
# --------------------------------------------------------------------------------------- #


def _q(
    memory_id: MemoryId,
    *,
    event_id: UUID | None = None,
    scored_at: datetime,
    new_q: float = 0.65,
) -> QUpdate:
    return QUpdate(
        memory_id=memory_id,
        event_id=event_id or uuid4(),
        principal_id=PrincipalId(uuid4()),
        previous_q=0.5,
        new_q=new_q,
        contribution=1.0,
        epoch_id=1,
        scored_at=scored_at,
    )


def _rebind(event: ScoringEvent, memory_id: MemoryId) -> ScoringEvent:
    """The same event, re-pointed at `memory_id` (parity runs two memories through one event
    stream; every candidate must belong to the batch's memory)."""
    return ScoringEvent(
        event_id=event.event_id,
        run_id=event.run_id,
        memory_id=memory_id,
        adapter=event.adapter,
        r=event.r,
        principal_id=event.principal_id,
        arrived_at=event.arrived_at,
        outcome_summary=event.outcome_summary,
    )


def _scored_use_count(pool: ConnectionPool, project_id: ProjectId, memory_id: MemoryId) -> int:
    with scoped(pool, project_id) as conn:
        row = conn.execute(
            "SELECT scored_use_count FROM memory_item WHERE project_id = %(p)s AND id = %(m)s",
            {"p": project_id, "m": memory_id},
        ).fetchone()
    assert row is not None
    return int(row[0])
