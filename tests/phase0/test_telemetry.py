"""PHASE-0 Task 16 / PHASE0-CONTRACT.md §5.4, §13.2: the `Telemetry` facade.

Two layers, matching the split the contract's offline-first rule (§12) draws for every chunk:

- The offline tests exercise `Telemetry` as pure delegation against a fake repository -- no
  database needed to prove it forwards exactly the row PLAN.md §2 invariant 2 requires, and that
  it satisfies `adapters.ports.TelemetryPort` structurally (the Protocol `hotpath/` will depend on
  in Phase 1, never on the concrete class).
- `test_telemetry.py` is also marked `[integration]` in the contract's test-ownership table
  (§13.2: "retrieval_event/injection rows land under caller's project"); the integration test here
  proves that against a real database, and that a project cannot see another project's rows
  through the same read path (the wall, restated for this table).
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence
from typing import Any

import pytest

from tracebed.adapters.ports import TelemetryPort
from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Arm, OutcomeCode, Slot
from tracebed.domain.ids import ProjectId, RunId, mint_memory_id, mint_run_id, uuid7
from tracebed.stores.pg.rows import InjectionRow, RetrievalEventInsert
from tracebed.stores.pg.telemetry import Telemetry

pytestmark = pytest.mark.phase0


def _require_fixture(request: pytest.FixtureRequest, name: str) -> Any:
    """Resolve an integration fixture, or skip -- matches the pattern already established in
    `test_repo_scoping.py` / `test_repo_provenance.py` for fixtures owned by chunk `harness`
    (`repo`, `pg_pool`, `two_projects`) that may not exist yet, so "the harness has not landed"
    is a clean skip rather than a fixture-lookup ERROR that reddens the gate for an unrelated
    reason (contract §12).
    """
    try:
        return request.getfixturevalue(name)
    except pytest.FixtureLookupError:
        pytest.skip(f"fixture {name!r} unavailable (tests/phase0/conftest.py, owner: harness)")


class FakeRepo:
    """Records exactly the two calls `Telemetry` may make. Not a `Repo` subclass -- mypy strict
    is not applied to `tests/` (pyproject.toml `[tool.mypy] packages = ["tracebed"]`), and a fake
    that merely has the right two methods is a stronger test of "Telemetry only calls these two
    methods, with these arguments" than a real `Repo` object would be off a live database.
    """

    def __init__(self) -> None:
        self.retrieval_calls: list[tuple[ProjectId, RetrievalEventInsert]] = []
        self.injection_calls: list[tuple[ProjectId, RunId, Sequence[InjectionRow]]] = []

    def insert_retrieval_event(self, project_id: ProjectId, row: RetrievalEventInsert) -> None:
        self.retrieval_calls.append((project_id, row))

    def insert_injection_rows(
        self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
    ) -> None:
        self.injection_calls.append((project_id, run_id, rows))


def test_telemetry_satisfies_telemetry_port() -> None:
    """`hotpath/` (Phase 1) depends on `TelemetryPort`, not on this concrete class.

    `isinstance` against a `@runtime_checkable` Protocol checks only that the ATTRIBUTE exists
    -- rename `outcome_code` to `code`, make `arm` positional, or drop `top_score`, and the
    isinstance assertion still passes while every keyword-argument call site breaks. So the
    parameter list is compared explicitly: this is the assertion that actually goes red when the
    concrete method drifts from the Protocol the hot path is typed against.
    """
    telemetry = Telemetry(FakeRepo(), FakeClock())  # type: ignore[arg-type]
    assert isinstance(telemetry, TelemetryPort)

    port_params = list(inspect.signature(TelemetryPort.record_retrieval).parameters.values())
    impl_params = list(inspect.signature(Telemetry.record_retrieval).parameters.values())
    assert [(p.name, p.kind) for p in impl_params] == [(p.name, p.kind) for p in port_params]
    assert [p.annotation for p in impl_params] == [p.annotation for p in port_params]


def test_record_retrieval_forwards_every_field_to_the_repo() -> None:
    """PLAN.md §2 invariant 2 / the task description: every retrieval writes a row -- this
    proves the row `Telemetry` builds carries every field it was given, unmodified, including
    the `None` fields a degraded/empty-result call legitimately has."""
    repo = FakeRepo()
    telemetry = Telemetry(repo, FakeClock())  # type: ignore[arg-type]
    project_id = ProjectId(uuid7())
    run_id = mint_run_id()

    telemetry.record_retrieval(
        project_id,
        run_id,
        outcome_code=OutcomeCode.TIMEOUT_PREFIX_ONLY,
        latency_ms=301,
        embed_latency_ms=None,
        candidates_considered=0,
        top_score=None,
        arm=Arm.MEMORY_ON,
    )

    assert len(repo.retrieval_calls) == 1
    got_project_id, row = repo.retrieval_calls[0]
    assert got_project_id == project_id
    assert row == RetrievalEventInsert(
        run_id=run_id,
        outcome_code=OutcomeCode.TIMEOUT_PREFIX_ONLY,
        latency_ms=301,
        embed_latency_ms=None,
        candidates_considered=0,
        top_score=None,
        arm=Arm.MEMORY_ON,
    )


def test_record_retrieval_writes_a_row_for_empty_result_too() -> None:
    """The exact distinction the task description calls out: `empty_result` (abstention, the
    system working) must land a row exactly like `timeout_prefix_only` (the system failing) --
    conflating "no row" with "abstained" would make Phase 3's lift computation blind to timeouts.
    `Telemetry` has no special case for any `OutcomeCode`; this pins that down for every value.
    """
    repo = FakeRepo()
    telemetry = Telemetry(repo, FakeClock())  # type: ignore[arg-type]

    for code in OutcomeCode:
        telemetry.record_retrieval(
            ProjectId(uuid7()),
            mint_run_id(),
            outcome_code=code,
            latency_ms=1,
            embed_latency_ms=1,
            candidates_considered=0,
            top_score=None,
            arm=Arm.HOLDOUT,
        )

    assert len(repo.retrieval_calls) == len(list(OutcomeCode))
    recorded_codes = {row.outcome_code for _pid, row in repo.retrieval_calls}
    assert recorded_codes == set(OutcomeCode)


def test_record_injections_forwards_rows_unmodified() -> None:
    repo = FakeRepo()
    telemetry = Telemetry(repo, FakeClock())  # type: ignore[arg-type]
    project_id = ProjectId(uuid7())
    run_id = mint_run_id()
    rows = (
        InjectionRow(memory_id=mint_memory_id(), slot=Slot.FACT, score=0.91, tokens=42),
        InjectionRow(memory_id=mint_memory_id(), slot=Slot.PITFALL, score=0.55, tokens=18),
    )

    telemetry.record_injections(project_id, run_id, rows)

    assert repo.injection_calls == [(project_id, run_id, rows)]


def test_record_injections_forwards_an_empty_sequence_too() -> None:
    """A retrieval that injected nothing still calls the repo -- `Telemetry` does not decide on
    its own that an empty sequence is "nothing to record"; `Repo.insert_injection_rows` is the
    one place that short-circuits (contract §5.1), and it does so on an executed empty statement,
    not on a call that never happened."""
    repo = FakeRepo()
    telemetry = Telemetry(repo, FakeClock())  # type: ignore[arg-type]
    project_id = ProjectId(uuid7())
    run_id = mint_run_id()

    telemetry.record_injections(project_id, run_id, ())

    assert repo.injection_calls == [(project_id, run_id, ())]


@pytest.mark.integration
def test_retrieval_and_injection_rows_land_under_callers_project_only(
    request: pytest.FixtureRequest, fake_clock: FakeClock
) -> None:
    """Contract §13.2's stated proof for this file: rows land under the caller's project, and
    -- the isolation half every telemetry write shares with every other partitioned table -- the
    other project in the fixture cannot read them back."""
    from tracebed.stores.pg.pool import scoped

    repo = _require_fixture(request, "repo")
    pg_pool = _require_fixture(request, "pg_pool")
    scope_a, scope_b = _require_fixture(request, "two_projects")

    telemetry = Telemetry(repo, fake_clock)
    run_id = mint_run_id()
    memory_id = mint_memory_id()

    telemetry.record_retrieval(
        scope_a.project_id,
        run_id,
        outcome_code=OutcomeCode.INJECTED,
        latency_ms=77,
        embed_latency_ms=12,
        candidates_considered=5,
        top_score=0.83,
        arm=Arm.MEMORY_ON,
    )
    telemetry.record_injections(
        scope_a.project_id,
        run_id,
        (InjectionRow(memory_id=memory_id, slot=Slot.FACT, score=0.83, tokens=40),),
    )

    with scoped(pg_pool, scope_a.project_id) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT project_id, outcome_code, latency_ms, arm FROM retrieval_event "
            "WHERE run_id = %(run_id)s",
            {"run_id": run_id},
        )
        retrieval_row = cur.fetchone()
        cur.execute(
            "SELECT memory_id, slot, tokens FROM injection_log WHERE run_id = %(run_id)s",
            {"run_id": run_id},
        )
        injection_rows = cur.fetchall()

    assert retrieval_row is not None
    assert str(retrieval_row[0]) == str(scope_a.project_id.value)
    assert retrieval_row[1] == OutcomeCode.INJECTED.value
    assert retrieval_row[2] == 77
    assert retrieval_row[3] == Arm.MEMORY_ON.value
    assert len(injection_rows) == 1
    assert str(injection_rows[0][0]) == str(memory_id.value)

    # The wall: project B's own scoped connection sees neither row for this run_id.
    with scoped(pg_pool, scope_b.project_id) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM retrieval_event WHERE run_id = %(run_id)s", {"run_id": run_id})
        assert cur.fetchone() is None
        cur.execute("SELECT 1 FROM injection_log WHERE run_id = %(run_id)s", {"run_id": run_id})
        assert cur.fetchone() is None
