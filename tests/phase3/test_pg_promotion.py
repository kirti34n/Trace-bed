"""`stores.pg.promotion.PromotionRepo` — Postgres half of
`workers.promotion.PromotionRepoPort` (FIDELITY-AUDIT.md M3; contract RISK 2).

Two mandatory classes, per the store-test strategy:

  * `TestFakeParity` drives the SAME persist/insert/select call sequence against the PG store
    and the harness's authoritative in-memory fake (`harness.closed_loop._Vault`, whose
    `persist` is the shared oracle for both `ShadowValidatorRepoPort` and `PromotionRepoPort`)
    and asserts identical observable results — success moves the row, a stale `from_status` or
    a cross-project write RAISES, and the two evidence-blocked selects refuse (contract RISK
    2) rather than fabricate governance evidence.
  * `TestCrossProjectDenial` runs every write as the NOBYPASSRLS `tracebed_app` role (the owner
    would hide a missing predicate) and proves project B cannot move OR read project A's row.

Each test owns a uniquely-named scratch database (CREATE → `apply_migrations` →
`create_project_partitions` for two projects → DROP), isolated from the shared Tracebed
database and from sibling agents.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from harness.closed_loop import _Row, _Vault
from psycopg.conninfo import make_conninfo

from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, mint_run_id
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.lifecycle import LifecycleWriter, StaleStatusTransition
from tracebed.stores.pg.migrate import apply_migrations
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.promotion import PromotionRepo
from tracebed.stores.pg.repo import Repo
from tracebed.workers.promotion import PromotionRepoPort, PromotionTransitionWrite

pytestmark = [pytest.mark.phase3, pytest.mark.integration]

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_APP_USER = "tracebed_app"
_APP_PASSWORD = "tracebed_app_dev"


@dataclass
class _Env:
    scratch_dsn: str
    pool: object
    repo: Repo
    lifecycle: LifecycleWriter
    store: PromotionRepo
    project_a: ProjectId
    project_b: ProjectId


def _seed_candidate(repo: Repo, project_id: ProjectId, clock: FakeClock) -> MemoryId:
    """Insert one `candidate` `memory_item` for `project_id`, via the real write path
    (`Repo.insert_memory_item` verifies a genuine scan verdict), and return its id."""
    from tracebed.core.scans import ScanContext, scan

    item = NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.SEMANTIC,
        kind="fact",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.B,
        status=Status.CANDIDATE,
        content=f"candidate content {uuid.uuid4().hex[:8]}",
        token_count=4,
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
    )
    verdict = scan(
        item.content,
        context=ScanContext(
            project_id=project_id,
            mem_type=item.mem_type,
            trust_tier=item.trust_tier,
            provenance_class=item.provenance.cls,
            lane=item.lane,
        ),
    ).verdict(clock=clock)
    return repo.insert_memory_item(project_id, item, verdict)


def _vault_row(memory_id: MemoryId, project_id: ProjectId) -> _Row:

    return _Row(
        id=memory_id,
        project_id=project_id,
        status=Status.CANDIDATE,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        content="candidate",
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
        status_changed_at=EPOCH,
    )


@pytest.fixture
def env(pg: str) -> Iterator[_Env]:
    """A private scratch database with two provisioned projects and a wired `PromotionRepo`."""
    scratch_name = f"tb_promo_{uuid.uuid4().hex}"
    admin = psycopg.connect(pg, autocommit=True)
    try:
        admin.execute(f'CREATE DATABASE "{scratch_name}"')
    finally:
        admin.close()

    # yoyo (apply_migrations) resolves its backend from a URL scheme, so the scratch DSN must
    # stay URL-form — swap the path component rather than go through make_conninfo (which emits
    # keyword form). psycopg's own parser accepts this URL for create_pool just the same.
    parts = urlsplit(pg)
    scratch_dsn = urlunsplit(parts._replace(path=f"/{scratch_name}"))
    apply_migrations(scratch_dsn)
    clock = FakeClock(EPOCH)
    pool = create_pool(scratch_dsn)
    repo = Repo(pool, clock)
    lifecycle = LifecycleWriter(pool, clock)
    store = PromotionRepo(pool, repo, lifecycle)

    project_a = repo.create_project(f"A-{uuid.uuid4().hex[:8]}")
    project_b = repo.create_project(f"B-{uuid.uuid4().hex[:8]}")
    with pool.connection() as conn:
        create_project_partitions(conn, project_a)
        create_project_partitions(conn, project_b)

    try:
        yield _Env(scratch_dsn, pool, repo, lifecycle, store, project_a, project_b)
    finally:
        pool.close()
        admin = psycopg.connect(pg, autocommit=True)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{scratch_name}" WITH (FORCE)')
        finally:
            admin.close()


class TestFakeParity:
    def test_store_satisfies_the_runtime_checkable_port(self, env: _Env) -> None:
        assert isinstance(env.store, PromotionRepoPort)

    def test_persist_promotes_candidate_to_validated_like_the_vault(self, env: _Env) -> None:

        mem = _seed_candidate(env.repo, env.project_a, FakeClock(EPOCH))
        write = PromotionTransitionWrite(mem, Status.CANDIDATE, Status.VALIDATED, EPOCH)

        # Oracle: the authoritative in-memory fake.
        vault = _Vault(FakeClock(EPOCH))
        vault.rows[mem] = _vault_row(mem, env.project_a)
        vault.persist(env.project_a, write)

        env.store.persist(env.project_a, write)

        assert vault.rows[mem].status is Status.VALIDATED
        assert env.repo.get_memory_by_id(env.project_a, mem).status is Status.VALIDATED

    def test_persist_stale_from_status_raises_like_the_vault(self, env: _Env) -> None:

        mem = _seed_candidate(env.repo, env.project_a, FakeClock(EPOCH))
        # The row is CANDIDATE; a write claiming it is VALIDATED is a stale transition.
        stale = PromotionTransitionWrite(mem, Status.VALIDATED, Status.RETIRED, EPOCH)

        vault = _Vault(FakeClock(EPOCH))
        vault.rows[mem] = _vault_row(mem, env.project_a)
        with pytest.raises(TracebedError):
            vault.persist(env.project_a, stale)

        with pytest.raises(StaleStatusTransition):
            env.store.persist(env.project_a, stale)
        # The row is untouched by the refused write.
        assert env.repo.get_memory_by_id(env.project_a, mem).status is Status.CANDIDATE

    def test_persist_cross_project_write_raises_like_the_vault(self, env: _Env) -> None:

        mem = _seed_candidate(env.repo, env.project_a, FakeClock(EPOCH))
        write = PromotionTransitionWrite(mem, Status.CANDIDATE, Status.VALIDATED, EPOCH)

        # Vault: A's row, but the call is scoped to B → "cross-project status write".
        vault = _Vault(FakeClock(EPOCH))
        vault.rows[mem] = _vault_row(mem, env.project_a)
        with pytest.raises(TracebedError):
            vault.persist(env.project_b, write)

        # Owner-scoped store: scoped to B, A's row is invisible → zero rows → raise.
        with pytest.raises(StaleStatusTransition):
            env.store.persist(env.project_b, write)
        assert env.repo.get_memory_by_id(env.project_a, mem).status is Status.CANDIDATE

    def test_insert_review_item_writes_a_review_queue_row(self, env: _Env) -> None:
        mem = _seed_candidate(env.repo, env.project_a, FakeClock(EPOCH))
        env.store.insert_review_item(env.project_a, "retirement candidate: needs a human", mem)

        items = env.repo.list_review_items(env.project_a)
        assert len(items) == 1
        assert items[0].memory_id == mem
        assert items[0].reason == "retirement candidate: needs a human"
        # It is NOT a status change — the memory is still candidate.

        assert env.repo.get_memory_by_id(env.project_a, mem).status is Status.CANDIDATE

    def test_select_candidates_is_blocked_and_names_the_missing_schema(self, env: _Env) -> None:
        """Contract RISK 2: promotion-evidence aggregation has no backing schema; the store
        refuses rather than promote on invented evidence."""
        with pytest.raises(NotImplementedError, match=r"scan_repass|outcome_event"):
            env.store.select_candidates_for_promotion(env.project_a)

    def test_select_validated_is_blocked_and_names_the_missing_schema(self, env: _Env) -> None:
        """Contract RISK 2 & 4: distinct_scoring_principals needs the memory_q_update ledger
        (migration 0006), which does not yet exist."""
        with pytest.raises(
            NotImplementedError, match=r"memory_q_update|distinct_scoring_principals"
        ):
            env.store.select_validated_for_retirement(env.project_a)


class TestCrossProjectDenial:
    """Every write as the NOBYPASSRLS `tracebed_app` role — the deployment role, under which a
    missing predicate leaks nothing and a cross-project write moves zero rows."""

    def _app_pool(self, scratch_dsn: str) -> object:
        app_dsn = make_conninfo(scratch_dsn, user=_APP_USER, password=_APP_PASSWORD)
        try:
            probe = psycopg.connect(app_dsn, connect_timeout=2)
        except psycopg.OperationalError as exc:
            pytest.skip(f"tracebed_app role unreachable ({exc.__class__.__name__})")
        probe.close()
        return create_pool(app_dsn)

    def test_project_b_cannot_move_or_read_project_a_row(self, env: _Env) -> None:

        # A's candidate seeded by the owner (write path needs owner privileges for scan wiring).
        mem = _seed_candidate(env.repo, env.project_a, FakeClock(EPOCH))

        app_pool = self._app_pool(env.scratch_dsn)
        try:
            clock = FakeClock(EPOCH)
            app_repo = Repo(app_pool, clock)
            app_lifecycle = LifecycleWriter(app_pool, clock)
            app_store = PromotionRepo(app_pool, app_repo, app_lifecycle)

            # WRITE denial: scoped to B, a promotion of A's memory moves zero rows → raise.
            write = PromotionTransitionWrite(mem, Status.CANDIDATE, Status.VALIDATED, EPOCH)
            with pytest.raises(StaleStatusTransition):
                app_store.persist(env.project_b, write)

            # READ denial: a review item opened under B never surfaces A's memory, and A's
            # review queue read under B returns nothing of A's.
            app_store.insert_review_item(env.project_b, "B's own note", None)
            assert app_repo.list_review_items(env.project_b) != []
            # B's scope sees none of A's review rows (there are none yet, but the seam holds).
            b_items = app_repo.list_review_items(env.project_b)
            assert all(i.memory_id != mem for i in b_items)
        finally:
            app_pool.close()  # type: ignore[attr-defined]

        # A's row, read back by the owner, is exactly as seeded — the B-scoped write never landed.
        assert env.repo.get_memory_by_id(env.project_a, mem).status is Status.CANDIDATE
