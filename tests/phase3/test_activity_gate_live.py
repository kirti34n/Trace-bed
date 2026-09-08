"""Scratch migration and minimal-schema proofs for activity advisory-lock behavior."""

from __future__ import annotations

from collections.abc import Iterator
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import psycopg
import pytest
from psycopg_pool import ConnectionPool

from tests.phase2.trace_e2e_support import _RedactedDsn
from tests.phase2.trace_e2e_support import scratch_dsn as scratch_dsn
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.errors import ActivityBusy, ProjectInactive
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.activity import ActivityGate, activity_lock_key, create_activity_pool

pytestmark = [pytest.mark.phase3, pytest.mark.integration]


@pytest.fixture
def activity_mechanics_dsn(pg: str) -> Iterator[str]:
    """Minimal owner-role mechanics fixture; not migration or bootstrap evidence."""

    database = f"tb_activity_gate_{uuid4().hex[:16]}"
    admin = psycopg.connect(pg, autocommit=True, connect_timeout=2)
    try:
        admin.execute(f'CREATE DATABASE "{database}"')
    except Exception as exc:  # pragma: no cover - environment capability probe
        admin.close()
        pytest.skip(f"cannot create isolated activity database: {exc.__class__.__name__}")
    dsn = urlunsplit(urlsplit(pg)._replace(path=f"/{database}"))
    try:
        with psycopg.connect(dsn) as conn:
            conn.execute(
                "CREATE TABLE project ("
                "project_id uuid PRIMARY KEY, name text NOT NULL, status text NOT NULL, "
                "deleted_at timestamptz NULL)"
            )
        yield _RedactedDsn(dsn)
    finally:
        try:
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()",
                (database,),
            )
            admin.execute(f'DROP DATABASE IF EXISTS "{database}"')
        finally:
            admin.close()


def _project(pool: ConnectionPool, *, status: str = "active") -> ProjectId:
    project_id = ProjectId(uuid4())
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO project (project_id, name, status, deleted_at) VALUES (%s, %s, %s, %s)",
            (project_id.value, f"activity-{project_id.value.hex}", "active", None),
        )
        if status == "suspended":
            conn.execute(
                "UPDATE project SET status = 'suspended' WHERE project_id = %s", (project_id.value,)
            )
        elif status == "deleted":
            conn.execute(
                "UPDATE project SET status = 'deleting' WHERE project_id = %s", (project_id.value,)
            )
            conn.execute(
                "UPDATE project SET status = 'deleted' WHERE project_id = %s", (project_id.value,)
            )
        elif status != "active":
            raise ValueError("unsupported test project status")
    return project_id


def test_activity_gate_shared_exclusive_release_and_project_state(scratch_dsn: str) -> None:
    with create_activity_pool(
        scratch_dsn,
        connect_timeout_s=2,
        checkout_timeout_s=2.0,
    ) as pool:
        gate = ActivityGate(pool)
        project_id = _project(pool)
        with gate.shared(project_id), gate.shared(project_id):
            pass
        with gate.exclusive(project_id), pytest.raises(ActivityBusy), gate.shared(project_id):
            pass
        with gate.exclusive(project_id), pytest.raises(ActivityBusy), gate.exclusive(project_id):
            pass
        with gate.shared(project_id):
            pass
        with gate.exclusive(project_id):
            pass

        for state_project in (
            _project(pool, status="suspended"),
            _project(pool, status="deleted"),
        ):
            with pytest.raises(ProjectInactive), gate.shared(state_project):
                pass


def test_activity_pool_reset_unlocks_a_leaked_session_lock(scratch_dsn: str) -> None:
    project_id = ProjectId(uuid4())
    key = activity_lock_key(project_id)
    with create_activity_pool(
        scratch_dsn,
        connect_timeout_s=2,
        checkout_timeout_s=2.0,
    ) as pool:
        with pool.connection() as conn:
            conn.execute("SELECT pg_advisory_lock(%s::bigint)", (key,))
        with psycopg.connect(scratch_dsn, autocommit=True) as observer:
            row = observer.execute("SELECT pg_try_advisory_lock(%s::bigint)", (key,)).fetchone()
            assert row is not None and row[0] is True
            observer.execute("SELECT pg_advisory_unlock(%s::bigint)", (key,))


def test_minimal_budgeted_activity_gate_lock_and_local_guc_mechanics(
    activity_mechanics_dsn: str,
) -> None:
    """Narrow owner-role mechanics coverage; canonical API coverage is in the cutover suite."""

    class Budget:
        def remaining_ms(self) -> float:
            return 500.0

    assert isinstance(Budget(), RemainingBudget)
    with create_activity_pool(
        activity_mechanics_dsn,
        connect_timeout_s=2,
        checkout_timeout_s=2.0,
        min_size=1,
        max_size=1,
    ) as pool:
        gate = ActivityGate(pool, cleanup_timeout_ms=17)
        project_id = _project(pool)
        key = activity_lock_key(project_id)
        with (
            gate.shared(project_id, deadline=Budget()),
            psycopg.connect(activity_mechanics_dsn, autocommit=True) as observer,
        ):
            assert observer.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone() == (
                False,
            )
        with psycopg.connect(activity_mechanics_dsn, autocommit=True) as observer:
            assert observer.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone() == (True,)
            assert observer.execute("SELECT pg_advisory_unlock(%s)", (key,)).fetchone() == (True,)
        with pool.connection() as conn:
            assert conn.execute("SHOW statement_timeout").fetchone() == ("0",)
            assert conn.execute("SHOW lock_timeout").fetchone() == ("0",)
