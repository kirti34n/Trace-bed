"""The scheduled TTL sweep, driven through `composition.build_scheduled_jobs`' real
per-project loop, proves PLAN.md §10 isolation END TO END against a live database under the
`tracebed_app` role (NOBYPASSRLS -- the owner bypasses RLS and would hide a missing predicate).

Two isolation claims, both measured through the app role:

(1) RLS-enforced sweep path. Seed a QUARANTINED row past its TTL in BOTH project A and project B,
    then run the composed `sweeps` job with `list_project_ids` returning ONLY [A]. Assert A's row
    transitioned to ARCHIVED and B's row is byte-for-byte the QUARANTINED row it was seeded as.
    The transition of A is itself the isolation proof: `run_all_sweeps(A, ...)` reads through a
    store scoped to A, so if A's `select_by_status(QUARANTINED)` leaked B's row the sweep would hit
    `workers.sweeps`' own invariant-4 guard and raise -- which `_per_project` would swallow, leaving
    A un-transitioned. A ending ARCHIVED therefore means no cross-project row entered A's batch.

(2) Predicate-enforced enumeration path. `agent_type` is an UNPARTITIONED registry table with no
    RLS (0003_rls.sql), so `Repo.list_agent_type_ids` is isolated by its explicit `WHERE
    project_id` predicate alone. Assert the app-role Repo returns exactly A's agent types and none
    of B's -- this asserts the predicate, NOT RLS, because there is no policy on this table for RLS
    to fall back on.

Runs against a private, uniquely-named scratch database (create -> apply_migrations ->
create_project_partitions for two projects -> test -> DROP), exactly like
`test_pg_memory_lifecycle.py`, and skips cleanly when no Postgres is reachable.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

pytestmark = [pytest.mark.phase2, pytest.mark.integration]

psycopg = pytest.importorskip("psycopg")
from psycopg.conninfo import make_conninfo  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402
from psycopg.types.json import Json  # noqa: E402

from tracebed.domain.clock import FakeClock  # noqa: E402
from tracebed.domain.config import ConfigResolver, TracebedSettings  # noqa: E402
from tracebed.domain.enums import MemType, ProvenanceClass  # noqa: E402
from tracebed.domain.ids import MemoryId, ProjectId, RunId  # noqa: E402
from tracebed.domain.memory import Provenance  # noqa: E402
from tracebed.domain.state_machine import Status  # noqa: E402
from tracebed.stores.pg.memory_lifecycle import MemoryLifecycleRepo  # noqa: E402
from tracebed.stores.pg.pool import create_pool, scoped  # noqa: E402
from tracebed.stores.pg.repo import Repo  # noqa: E402
from tracebed.workers.composition import LearningPlane, build_scheduled_jobs  # noqa: E402

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)

_SEED_SQL = """
INSERT INTO memory_item (
    id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier,
    status, content, content_hash, token_count, provenance, scan_verdict_id,
    strike_count, q_value, status_changed_at, last_retrieved_at, created_at
) VALUES (
    %(id)s, %(project_id)s, 'project_shared', NULL, %(mem_type)s, 'k', 'operational', 'B',
    %(status)s, 'c', 'h', 1, %(provenance)s, %(scan_verdict_id)s,
    0, 0.5, %(status_changed_at)s, NULL, %(created_at)s
)
"""

_READ_RAW_SQL = """
SELECT status, status_changed_at FROM memory_item
WHERE project_id = %(project_id)s AND id = %(id)s
"""


@dataclass
class _Env:
    owner_pool: Any
    app_pool: Any
    settings: TracebedSettings
    project_a: ProjectId
    project_b: ProjectId


@pytest.fixture(scope="module")
def env() -> Iterator[_Env]:
    import os

    owner_dsn = os.environ.get("TB_STORAGE__PG_DSN")
    if not owner_dsn:
        pytest.skip("TB_STORAGE__PG_DSN is not set — no Postgres available")

    db_name = f"tb_sweepisol_{uuid.uuid4().hex[:12]}"
    try:
        admin = psycopg.connect(owner_dsn, autocommit=True, connect_timeout=2)
    except Exception as exc:  # pragma: no cover - environment probe
        pytest.skip(f"Postgres unreachable (TB_STORAGE__PG_DSN): {exc}")

    with admin:
        admin.execute(f'CREATE DATABASE "{db_name}"')
        owner_pool = None
        app_pool = None
        try:
            from urllib.parse import urlsplit, urlunsplit

            scratch_dsn = urlunsplit(urlsplit(owner_dsn)._replace(path=f"/{db_name}"))

            from tracebed.stores.pg.migrate import apply_migrations
            from tracebed.stores.pg.partitions import create_project_partitions

            apply_migrations(scratch_dsn)

            project_a = ProjectId(uuid.uuid4())
            project_b = ProjectId(uuid.uuid4())
            owner_pool = create_pool(scratch_dsn)
            with owner_pool.connection() as conn:
                # Registry rows so `agent_type`'s project_id FK resolves (the sweep test needs
                # only the partitions, but the agent-type enumeration test creates agent types).
                for pid in (project_a, project_b):
                    conn.execute(
                        "INSERT INTO project (project_id, name) VALUES (%(id)s, %(name)s)",
                        {"id": pid, "name": f"sweep-isol-{pid}"},
                    )
                create_project_partitions(conn, project_a)
                create_project_partitions(conn, project_b)

            app_dsn = make_conninfo(scratch_dsn, user="tracebed_app", password="tracebed_app_dev")
            app_pool = create_pool(app_dsn)

            # A connection-safe settings object: only its section DEFAULTS are read by the
            # resolver (the store is the source of per-project overrides), and its DSN is never
            # dialed. Built from the ambient env, which in the live harness carries only
            # storage/embedding/holdout vars — none of which touch lifecycle/scoring defaults, so
            # the quarantine TTL and q_start>archive_floor invariant hold at their documented
            # values.
            settings = TracebedSettings()

            yield _Env(owner_pool, app_pool, settings, project_a, project_b)
        finally:
            if owner_pool is not None:
                owner_pool.close()
            if app_pool is not None:
                app_pool.close()
            admin.execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')


@pytest.fixture(autouse=True)
def _clean(env: _Env) -> None:
    for p in (env.project_a, env.project_b):
        with scoped(env.owner_pool, p) as conn:
            conn.execute("DELETE FROM memory_item WHERE project_id = %(p)s", {"p": p})


def _seed_quarantined(env: _Env, project_id: ProjectId, mem_id: MemoryId) -> None:
    """One QUARANTINED row whose `status_changed_at` is well past the 30-day quarantine TTL."""
    prov = Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid.uuid4()),))
    params = {
        "id": mem_id,
        "project_id": project_id,
        "mem_type": MemType.LESSON.value,
        "status": Status.QUARANTINED.value,
        "provenance": Json(prov.to_json()),
        "scan_verdict_id": uuid.uuid4(),
        "status_changed_at": EPOCH,
        "created_at": EPOCH,
    }
    with scoped(env.owner_pool, project_id) as conn:
        conn.execute(_SEED_SQL, params)


def _read_status(env: _Env, project_id: ProjectId, mem_id: MemoryId) -> dict[str, object]:
    with scoped(env.owner_pool, project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(_READ_RAW_SQL, {"project_id": project_id, "id": mem_id})
        row = cur.fetchone()
    assert row is not None
    return row


def _plane(env: _Env) -> LearningPlane:
    """A `LearningPlane` whose ONLY live field is the app-role `MemoryLifecycleRepo` the sweeps
    job reads; every other field is an unused placeholder (the sweeps job touches none of them,
    and this test runs only the sweeps job)."""
    return LearningPlane(
        lifecycle=object(),  # type: ignore[arg-type]
        edit_ops=object(),  # type: ignore[arg-type]
        forensics=object(),  # type: ignore[arg-type]
        preferences=object(),  # type: ignore[arg-type]
        embedder=object(),  # type: ignore[arg-type]
        corroboration=None,
        memory_lifecycle=MemoryLifecycleRepo(env.app_pool),
        derived_state_store=object(),  # type: ignore[arg-type]
        scorer_repo=object(),  # type: ignore[arg-type]
        promotion_repo=object(),  # type: ignore[arg-type]
        shadow_validator_repo=object(),  # type: ignore[arg-type]
        killswitch_writer=object(),  # type: ignore[arg-type]
        known_distillations=object(),  # type: ignore[arg-type]
    )


class _NoopPrefixCache:
    """Unused here (only the sweeps job is run), but `build_scheduled_jobs` constructs the
    prefix builder, so a `StaticPrefixCachePort`-shaped object must be supplied."""

    def static_prefix_set(self, *a: Any, **k: Any) -> None:  # pragma: no cover - never called
        del a, k

    def current_prefix_version_set(self, *a: Any, **k: Any) -> None:  # pragma: no cover
        del a, k


def _sweeps_job(env: _Env, projects: list[ProjectId]) -> Any:
    """The real composed `sweeps` job, wired against the live app-role stores. `clock` is set 31
    days past the epoch so the seeded QUARANTINED rows are past their 30-day TTL."""
    app_repo = Repo(env.app_pool, FakeClock(EPOCH + timedelta(days=31)))
    resolver = ConfigResolver(env.settings, app_repo)
    jobs = build_scheduled_jobs(
        _plane(env),
        cfg=env.settings.workers,
        list_project_ids=lambda: list(projects),
        queue_observability=_Queue(),
        topics=("trace_event",),
        lease_seconds=30,
        clock=FakeClock(EPOCH + timedelta(days=31)),
        config_resolver=resolver,
        memory_store=app_repo,
        prefix_cache=_NoopPrefixCache(),
        list_agent_type_ids=app_repo.list_agent_type_ids,
        candidate_source=None,
    )
    return next(j for j in jobs if j.name == "sweeps")


class _Queue:
    def depth(self, topic: str) -> int:
        del topic
        return 0

    def dead_letter_count(self, topic: str) -> int:
        del topic
        return 0

    def oldest_age_s(self, topic: str) -> float | None:
        del topic
        return None

    def xmin_horizon_alarm(self) -> bool:
        return False


# --------------------------------------------------------------------------- #
# (1) RLS-enforced sweep isolation, driven through the per-project loop.
# --------------------------------------------------------------------------- #


def test_scheduled_sweep_archives_only_the_swept_project_and_leaves_the_other_untouched(
    env: _Env,
) -> None:
    a, b = env.project_a, env.project_b
    a_id = MemoryId(uuid.UUID(int=0xA1))
    b_id = MemoryId(uuid.UUID(int=0xB1))
    _seed_quarantined(env, a, a_id)
    _seed_quarantined(env, b, b_id)

    # The loop is handed ONLY project A. B is a fully-seeded neighbour that must not be touched
    # — neither by the loop (it never lists B) nor via any leak while A is swept.
    _sweeps_job(env, [a]).run()

    a_row = _read_status(env, a, a_id)
    b_row = _read_status(env, b, b_id)

    # A's row transitioned — which also proves A's sweep never saw B's row (a leak would have
    # raised invariant-4 inside run_all_sweeps and left A QUARANTINED).
    assert a_row["status"] == Status.ARCHIVED.value
    # B is byte-for-byte the row it was seeded as.
    assert b_row["status"] == Status.QUARANTINED.value
    assert b_row["status_changed_at"] == EPOCH


def test_the_loop_sweeps_every_project_it_is_given_each_in_its_own_scope(env: _Env) -> None:
    """The positive control for the isolation test above: when the loop IS given both projects,
    both are swept — so the untouched-B result above is the loop honouring its project list, not
    the sweep being inert."""
    a, b = env.project_a, env.project_b
    a_id = MemoryId(uuid.UUID(int=0xA2))
    b_id = MemoryId(uuid.UUID(int=0xB2))
    _seed_quarantined(env, a, a_id)
    _seed_quarantined(env, b, b_id)

    _sweeps_job(env, [a, b]).run()

    assert _read_status(env, a, a_id)["status"] == Status.ARCHIVED.value
    assert _read_status(env, b, b_id)["status"] == Status.ARCHIVED.value


# --------------------------------------------------------------------------- #
# (2) Predicate-enforced agent-type enumeration isolation.
# --------------------------------------------------------------------------- #


def test_list_agent_type_ids_returns_only_the_projects_own_agent_types(env: _Env) -> None:
    """`agent_type` has no RLS, so this asserts the explicit `WHERE project_id` predicate — the
    ONLY thing isolating one project's agent types from another's. Measured under the app role."""
    a, b = env.project_a, env.project_b
    owner_repo = Repo(env.owner_pool, FakeClock(EPOCH))
    a1 = owner_repo.create_agent_type(a, "agent-a1")
    a2 = owner_repo.create_agent_type(a, "agent-a2")
    b1 = owner_repo.create_agent_type(b, "agent-b1")

    app_repo = Repo(env.app_pool, FakeClock(EPOCH))
    got_a = set(app_repo.list_agent_type_ids(a))

    assert got_a == {a1, a2}
    assert b1 not in got_a
    # And the symmetric read for B excludes A's ids.
    assert set(app_repo.list_agent_type_ids(b)) == {b1}


def test_list_agent_type_ids_of_a_project_with_none_is_empty(env: _Env) -> None:
    """A project provisioned with no agent types yields an empty enumeration — the prefix
    builder's inner loop then does nothing that tick, no special-casing required."""
    app_repo = Repo(env.app_pool, FakeClock(EPOCH))
    isolated = ProjectId(uuid.uuid4())
    # No partitions/registry rows for `isolated`; the registry read simply matches nothing.
    assert app_repo.list_agent_type_ids(isolated) == []
