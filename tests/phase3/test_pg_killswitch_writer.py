"""`stores.pg.killswitch.KillswitchWriter` — the write half of `killswitch_state`.

Live-DB test on its OWN uniquely-named scratch database (create -> apply_migrations ->
provision two projects A and B -> test -> DROP), isolated from the shared `tracebed` DB and from
sibling agents. Two mandatory classes per the contract:

  (a) Fake-parity — `isinstance(writer, KillswitchStorePort)` (runtime_checkable), then the SAME
      call sequence driven against the PG writer and the worker's own `_FakeKillswitchStore`
      (imported, not re-declared), asserting they agree on every property the worker relies on:
      the write happened with these exact args; the PG store additionally UPSERTS (one row per
      scope cell, latest decision wins) rather than appending, which is the real-table semantics
      `workers/killswitch.py:76` mandates and which the spy fake cannot model.

  (b) Cross-project denial under `tracebed_app` (NOBYPASSRLS) — `killswitch_state` is a 0001
      registry table with NO RLS, so the meaningful isolation check is predicate/arbiter
      correctness, not a GUC-unset zero-rows probe: writing the same `(mem_type, agent_type)` cell
      under A and B produces two DISTINCT rows, each carrying its own `project_id`, and a B-scoped
      write can never overwrite A's row.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from tests.phase3.test_killswitch import _FakeKillswitchStore
from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import MemType
from tracebed.stores.pg.killswitch import KillswitchWriter
from tracebed.stores.pg.migrate import apply_migrations
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.repo import Repo
from tracebed.workers.killswitch import KillswitchStorePort

pytestmark = [pytest.mark.phase3, pytest.mark.integration]

# The owner DSN the workflow injects (TB_STORAGE__PG_DSN). Without it there is no database to
# talk to, so the whole module skips cleanly — matching every other live-DB test here.
_OWNER_DSN = os.environ.get("TB_STORAGE__PG_DSN")

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
MOMENT_1 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
MOMENT_2 = datetime(2026, 6, 2, 8, 30, tzinfo=UTC)

# A worker-shaped auto-trigger evidence payload (mirrors `workers.killswitch._evidence`) and an
# operator-override one — the two `evidence["source"]` tags the readers distinguish on.
_AUTO_EVIDENCE: dict[str, object] = {
    "source": "auto_killswitch",
    "reason": "task_quality_lift",
    "adverse_direction": "lower",
    "sustained": True,
    "min_n_satisfied": True,
    "bh_significant": True,
    "days_covered": 14,
    "window_days": 14,
    "lower_bound": -0.12,
    "point_estimate": -0.05,
    "p_value": 0.011,
    "n_treatment": 420,
    "n_control": 400,
}
_OVERRIDE_EVIDENCE: dict[str, object] = {
    "source": "operator_override",
    "reason": "task_quality_lift",
    "principal_id": str(uuid.uuid4()),
    "override_reason": "false positive; re-enabling by hand",
}


class _Fixture:
    """A provisioned scratch DB: owner pool + Repo, two projects with an agent type each."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.pool = create_pool(dsn)
        self.repo = Repo(self.pool, FakeClock(EPOCH))
        self.project_a = self.repo.create_project(f"ks-a-{uuid.uuid4().hex[:8]}")
        self.project_b = self.repo.create_project(f"ks-b-{uuid.uuid4().hex[:8]}")
        with self.pool.connection() as conn:
            create_project_partitions(conn, self.project_a)
            create_project_partitions(conn, self.project_b)
        self.agent_a = self.repo.create_agent_type(self.project_a, "planner")
        self.agent_b = self.repo.create_agent_type(self.project_b, "planner")

    def close(self) -> None:
        self.pool.close()


@pytest.fixture()
def fx() -> Iterator[_Fixture]:
    if _OWNER_DSN is None:
        pytest.skip("TB_STORAGE__PG_DSN not set; live Postgres required")
    scratch = f"tb_ks_writer_{uuid.uuid4().hex}"
    admin = psycopg.connect(_OWNER_DSN, autocommit=True)
    try:
        admin.execute(f'CREATE DATABASE "{scratch}"')
    finally:
        admin.close()
    # yoyo (apply_migrations) needs URL form, so swap the path rather than emit keyword conninfo.
    parts = urlsplit(_OWNER_DSN)
    dsn = urlunsplit(parts._replace(path=f"/{scratch}"))
    apply_migrations(dsn)
    fixture = _Fixture(dsn)
    try:
        yield fixture
    finally:
        fixture.close()
        admin = psycopg.connect(_OWNER_DSN, autocommit=True)
        try:
            admin.execute(f'DROP DATABASE "{scratch}" WITH (FORCE)')
        finally:
            admin.close()


# --------------------------------------------------------------------------------------- #
# (a) Fake-parity.
# --------------------------------------------------------------------------------------- #


class TestFakeParity:
    def test_writer_satisfies_the_runtime_checkable_port(self, fx: _Fixture) -> None:
        assert isinstance(KillswitchWriter(fx.pool), KillswitchStorePort)

    def test_same_call_records_the_same_cell_in_both_stores(self, fx: _Fixture) -> None:
        """Drive one identical call against the PG writer and the worker's spy fake; both must
        register the write with the exact args the worker passed."""
        pg = KillswitchWriter(fx.pool)
        fake = _FakeKillswitchStore()
        for store in (pg, fake):
            store.write_killswitch_state(
                fx.project_a,
                fx.agent_a,
                MemType.LESSON,
                disabled=True,
                evidence=_AUTO_EVIDENCE,
                changed_at=MOMENT_1,
            )

        # Fake: recorded verbatim.
        assert fake.calls == [
            {
                "project_id": fx.project_a,
                "agent_type_id": fx.agent_a,
                "mem_type": MemType.LESSON,
                "disabled": True,
                "evidence": _AUTO_EVIDENCE,
                "changed_at": MOMENT_1,
            }
        ]
        # PG: the same cell, readable back through the established reader.
        rows = fx.repo.list_killswitch_state(fx.project_a)
        assert len(rows) == 1
        row = rows[0]
        assert row.agent_type_id == fx.agent_a
        assert row.mem_type is MemType.LESSON
        assert row.disabled is True
        assert row.evidence == _AUTO_EVIDENCE  # jsonb round-trips the worker's keys verbatim
        assert row.changed_at == MOMENT_1  # persisted from the PARAMETER, not a clock/DEFAULT

    def test_retriggering_the_same_cell_upserts_not_appends(self, fx: _Fixture) -> None:
        """The real-table semantics the spy fake cannot model (`workers/killswitch.py:76`): the
        second decision on the same scope cell OVERWRITES the first — one row, latest wins —
        whereas the fake accumulates both calls."""
        pg = KillswitchWriter(fx.pool)
        fake = _FakeKillswitchStore()
        # First: auto-disable. Second: operator re-enable of the SAME cell.
        for store in (pg, fake):
            store.write_killswitch_state(
                fx.project_a, fx.agent_a, MemType.SEMANTIC,
                disabled=True, evidence=_AUTO_EVIDENCE, changed_at=MOMENT_1,
            )
            store.write_killswitch_state(
                fx.project_a, fx.agent_a, MemType.SEMANTIC,
                disabled=False, evidence=_OVERRIDE_EVIDENCE, changed_at=MOMENT_2,
            )

        assert len(fake.calls) == 2  # spy: append-only
        rows = [r for r in fx.repo.list_killswitch_state(fx.project_a) if r.mem_type is MemType.SEMANTIC]
        assert len(rows) == 1  # upsert: one row per cell
        assert rows[0].disabled is False
        assert rows[0].evidence == _OVERRIDE_EVIDENCE
        assert rows[0].changed_at == MOMENT_2

    def test_project_wide_null_agent_row_is_written_and_resolved(self, fx: _Fixture) -> None:
        """`agent_type_id=None` writes the project-wide overlay row (`agent_type_id IS NULL`),
        distinct from the agent-type-specific cell; `get_killswitch_overlay` ORs the two."""
        pg = KillswitchWriter(fx.pool)
        pg.write_killswitch_state(
            fx.project_a, None, MemType.PREFERENCE,
            disabled=True, evidence=_AUTO_EVIDENCE, changed_at=MOMENT_1,
        )
        rows = fx.repo.list_killswitch_state(fx.project_a)
        assert [r.agent_type_id for r in rows] == [None]
        # Both the project-wide (NULL) and any agent-type query see the disable.
        assert fx.repo.get_killswitch_overlay(fx.project_a, fx.agent_a) == {"preference": True}
        assert fx.repo.get_killswitch_overlay(fx.project_a, None) == {"preference": True}

    def test_overlay_or_semantics_project_wide_disable_beats_agent_enable(self, fx: _Fixture) -> None:
        pg = KillswitchWriter(fx.pool)
        pg.write_killswitch_state(
            fx.project_a, None, MemType.EPISODIC,
            disabled=True, evidence=_AUTO_EVIDENCE, changed_at=MOMENT_1,
        )
        pg.write_killswitch_state(
            fx.project_a, fx.agent_a, MemType.EPISODIC,
            disabled=False, evidence=_OVERRIDE_EVIDENCE, changed_at=MOMENT_2,
        )
        # Two distinct rows (NULL scope + agent scope); overlay ORs to disabled.
        assert len(fx.repo.list_killswitch_state(fx.project_a)) == 2
        assert fx.repo.get_killswitch_overlay(fx.project_a, fx.agent_a) == {"episodic": True}


# --------------------------------------------------------------------------------------- #
# (b) Cross-project denial under tracebed_app (NOBYPASSRLS).
# --------------------------------------------------------------------------------------- #


class TestCrossProjectDenial:
    def _app_pool(self, fx: _Fixture) -> object:
        return create_pool(make_conninfo(fx.dsn, user="tracebed_app", password="tracebed_app_dev"))

    def test_b_scoped_write_of_the_same_cell_cannot_overwrite_a(self, fx: _Fixture) -> None:
        """Seed A's cell, then — through a NOBYPASSRLS `tracebed_app` connection — write the SAME
        `(mem_type, agent_type)` scoped to B. The arbiter carries `project_id`, so B's write can
        only ever land under B: two distinct rows result, A's is untouched, and each project's
        overlay reads only its own."""
        app_pool = self._app_pool(fx)
        try:
            writer = KillswitchWriter(app_pool)  # type: ignore[arg-type]
            # A disables LESSON for agent_a.
            writer.write_killswitch_state(
                fx.project_a, fx.agent_a, MemType.LESSON,
                disabled=True, evidence=_AUTO_EVIDENCE, changed_at=MOMENT_1,
            )
            # B, scoped to B, targets the SAME agent_type_id and mem_type but with disabled=False.
            writer.write_killswitch_state(
                fx.project_b, fx.agent_a, MemType.LESSON,
                disabled=False, evidence=_OVERRIDE_EVIDENCE, changed_at=MOMENT_2,
            )
        finally:
            app_pool.close()  # type: ignore[attr-defined]

        # A's row is untouched by B's write.
        a_rows = fx.repo.list_killswitch_state(fx.project_a)
        assert len(a_rows) == 1
        assert a_rows[0].disabled is True
        assert a_rows[0].evidence == _AUTO_EVIDENCE
        assert a_rows[0].changed_at == MOMENT_1

        # B has its OWN distinct row under its own project_id.
        b_rows = fx.repo.list_killswitch_state(fx.project_b)
        assert len(b_rows) == 1
        assert b_rows[0].disabled is False
        assert b_rows[0].evidence == _OVERRIDE_EVIDENCE

        # Each overlay resolves to only its own decision.
        assert fx.repo.get_killswitch_overlay(fx.project_a, fx.agent_a) == {"lesson": True}
        assert fx.repo.get_killswitch_overlay(fx.project_b, fx.agent_a) == {"lesson": False}

    def test_b_scoped_reader_never_sees_a_rows(self, fx: _Fixture) -> None:
        """The predicate is the only row-scoping control on this non-RLS table; a B-scoped read of
        A's data must return nothing for A."""
        app_pool = self._app_pool(fx)
        try:
            KillswitchWriter(app_pool).write_killswitch_state(  # type: ignore[arg-type]
                fx.project_a, fx.agent_a, MemType.SEMANTIC,
                disabled=True, evidence=_AUTO_EVIDENCE, changed_at=MOMENT_1,
            )
        finally:
            app_pool.close()  # type: ignore[attr-defined]

        # B sees none of A's rows; A sees its own.
        assert fx.repo.list_killswitch_state(fx.project_b) == []
        assert fx.repo.get_killswitch_overlay(fx.project_b, fx.agent_a) == {}
        assert len(fx.repo.list_killswitch_state(fx.project_a)) == 1
