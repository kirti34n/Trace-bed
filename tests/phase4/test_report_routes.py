"""The D-093 aggregate report routes: `/admin/lift/report`, `/admin/staleness/report`,
`/admin/consolidation/diffs`, `/admin/injections` (`api/reports.py`).

Fully offline via `TestClient` + fake `AppDeps` + a fake `ReportsRepo`, the same shape
`tests/phase0/test_admin_routes.py` and `tests/phase0/test_control_plane_routes.py` use for the
sibling read routes. What these tests are actually for:

1. **Invariant 4 by construction.** Every route is `ScopeDep`-authenticated and reads only
   `scope.project_id` -- never a caller-supplied one. `test_project_id_is_never_read_off_the_request`
   proves a `project_id` query parameter changes nothing.
2. **Fail-closed on a missing reader.** No `reports_store` attached to `app.state` is a 500, not
   an empty report -- the same discipline `api.admin._control_plane` already enforces for the
   sibling D-093 routes.
3. **A cell under `killswitch.min_cell_n` is marked insufficient, never dropped** -- and a cell
   with fewer than 2 observations in an arm has no computable bound at all, reported as `None`
   fields plus `insufficient=True`, never a fabricated number.
4. **Pagination bounds the response** at the wire (422 outside `[1, MAX_REPORT_LIMIT]`), on
   every route that accepts `limit`/`offset`.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tracebed.adapters.identity import Principal
from tracebed.api.deps import AppDeps
from tracebed.api.main import create_app
from tracebed.api.reports import _bh_adjusted_p_values
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import AuthConfig, EmbeddingConfig, StorageConfig, TracebedSettings
from tracebed.domain.enums import Arm, MemType, OutcomeCode, ProvenanceClass
from tracebed.domain.errors import AuthenticationFailed, NotFound
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.scope import ProjectScope
from tracebed.stores.pg.reports import (
    MAX_LIFT_OBSERVATIONS,
    ConsolidationDiffRow,
    InjectionFeedRow,
    InvalidationReportRow,
    LiftRunObservationRow,
    QTrajectoryPointRow,
    RevalidationCandidateRow,
    StaleMemoryRow,
)

pytestmark = pytest.mark.phase4

EPOCH = datetime(2026, 3, 15, 12, 0, tzinfo=UTC)

PROJECT = ProjectId(UUID("11111111-1111-1111-1111-111111111111"))
OTHER_PROJECT = ProjectId(UUID("22222222-2222-2222-2222-222222222222"))
AGENT_TYPE = AgentTypeId(UUID("33333333-3333-3333-3333-333333333333"))
PRINCIPAL = PrincipalId(UUID("44444444-4444-4444-4444-444444444444"))
MEMORY = MemoryId(UUID("55555555-5555-5555-5555-555555555555"))

AUTH = {"x-api-key": "a-valid-tenant-key"}

ROUTES = [
    "/admin/lift/report",
    "/admin/staleness/report",
    "/admin/consolidation/diffs",
    "/admin/injections",
]


# --------------------------------------------------------------------------- #
# Fakes -- AppDeps side (identical shape to test_control_plane_routes.py; this
# route set never touches memory_reader/exporter/invalidations/admin/partitions/keys).
# --------------------------------------------------------------------------- #


class _AuthenticatesVerifier:
    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        if not authorization and not api_key:
            raise AuthenticationFailed("no credential presented")
        return Principal(principal_id=PRINCIPAL, kind="api_key", external_ref="ref")


class _Resolver:
    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        return ProjectScope(project_id=PROJECT, agent_type_id=AGENT_TYPE, principal_id=principal_id)


class _NeverCalledQueue:
    def enqueue(self, *args: object, **kwargs: object) -> int:
        raise AssertionError("no report route enqueues")


class _NeverCalledTelemetry:
    def record_retrieval(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("no report route records telemetry")


class _NeverCalledAdmin:
    def create_project(self, *args: object, **kwargs: object) -> ProjectId:
        raise AssertionError("no report route writes the registry")

    def create_agent_registration(self, *args: object, **kwargs: object) -> tuple[PrincipalId, AgentTypeId]:
        raise AssertionError("no report route writes the registry")


class _Stubs:
    """Ports the report routes never touch, but `AppDeps` requires."""

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> Any:
        raise NotFound("not found")

    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]:
        return iter(())

    def insert_invalidation_event(self, *args: object, **kwargs: object) -> UUID:
        raise AssertionError("no read route writes")

    def create_project_partitions(self, project_id: ProjectId) -> None:
        raise AssertionError("no read route provisions partitions")

    def ensure_project_kek(self, project_id: ProjectId) -> None:
        raise AssertionError("no read route provisions keys")


# --------------------------------------------------------------------------- #
# Fake -- the ReportsRepo-shaped store this chunk's routes actually read.
# --------------------------------------------------------------------------- #


@dataclass
class FakeReportsStore:
    seen_projects: list[ProjectId] = field(default_factory=list)
    lift_rows: list[LiftRunObservationRow] = field(default_factory=list)
    q_rows: list[QTrajectoryPointRow] = field(default_factory=list)
    invalidation_rows: list[InvalidationReportRow] = field(default_factory=list)
    stale_rows: list[StaleMemoryRow] = field(default_factory=list)
    revalidation_rows: list[RevalidationCandidateRow] = field(default_factory=list)
    consolidation_rows: list[ConsolidationDiffRow] = field(default_factory=list)
    injection_rows: list[InjectionFeedRow] = field(default_factory=list)
    last_limit: int | None = None
    last_offset: int | None = None
    last_since: datetime | None = None
    force_row_count: int | None = None
    """Pads the returned row list out to this length (recycling `lift_rows`) so a test can
    exercise the at-the-cap branch without materialising 50,000 distinct fixtures."""

    def lift_observations(
        self, project_id: ProjectId, *, since: datetime, limit: int = 50_000
    ) -> list[LiftRunObservationRow]:
        self.seen_projects.append(project_id)
        self.last_since = since
        rows = list(self.lift_rows)
        if self.force_row_count is not None and rows:
            while len(rows) < self.force_row_count:
                rows.append(rows[len(rows) % len(self.lift_rows)])
            rows = rows[: self.force_row_count]
        return rows

    def q_trajectory(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[QTrajectoryPointRow]:
        self.seen_projects.append(project_id)
        self.last_limit, self.last_offset = limit, offset
        return list(self.q_rows)

    def invalidation_events(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[InvalidationReportRow]:
        self.seen_projects.append(project_id)
        self.last_limit, self.last_offset = limit, offset
        return list(self.invalidation_rows)

    def stale_memories(self, project_id: ProjectId, *, limit: int = 5_000) -> list[StaleMemoryRow]:
        self.seen_projects.append(project_id)
        return list(self.stale_rows)

    def revalidation_candidates(
        self,
        project_id: ProjectId,
        *,
        threshold_at: datetime,
        now: datetime,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RevalidationCandidateRow]:
        self.seen_projects.append(project_id)
        self.last_limit, self.last_offset = limit, offset
        return list(self.revalidation_rows)

    def consolidation_diffs(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[ConsolidationDiffRow]:
        self.seen_projects.append(project_id)
        self.last_limit, self.last_offset = limit, offset
        return list(self.consolidation_rows)

    def injection_feed(
        self, project_id: ProjectId, *, limit: int = 100, offset: int = 0
    ) -> list[InjectionFeedRow]:
        self.seen_projects.append(project_id)
        self.last_limit, self.last_offset = limit, offset
        return list(self.injection_rows)


def _build(reports_store: FakeReportsStore | None) -> tuple[TestClient, FakeReportsStore | None]:
    stubs = _Stubs()
    deps = AppDeps(
        verifier=_AuthenticatesVerifier(),
        resolver=_Resolver(),
        queue=_NeverCalledQueue(),
        telemetry=_NeverCalledTelemetry(),
        memory_reader=stubs,
        exporter=stubs,
        invalidations=stubs,
        admin=_NeverCalledAdmin(),
        partitions=stubs,
        keys=stubs,
        clock=FakeClock(EPOCH),
    )
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
        embedding=EmbeddingConfig(model_version="test"),
        auth=AuthConfig(admin_key_env="TB_TEST_UNUSED_ADMIN_KEY"),
    )
    app: FastAPI = create_app(settings, deps)
    if reports_store is not None:
        app.state.reports_store = reports_store
    return TestClient(app), reports_store


@pytest.fixture
def harness() -> tuple[TestClient, FakeReportsStore]:
    store = FakeReportsStore()
    client, _ = _build(store)
    return client, store


# --------------------------------------------------------------------------- #
# Auth + isolation + fail-closed, shared across all four routes.
# --------------------------------------------------------------------------- #


class TestAuthAndIsolation:
    @pytest.mark.parametrize("path", ROUTES)
    def test_unauthenticated_is_401_before_any_read(
        self, harness: tuple[TestClient, FakeReportsStore], path: str
    ) -> None:
        client, store = harness
        assert client.get(path).status_code == 401
        assert store.seen_projects == []

    @pytest.mark.parametrize("path", ROUTES)
    def test_authenticated_reads_use_the_derived_scope(
        self, harness: tuple[TestClient, FakeReportsStore], path: str
    ) -> None:
        client, store = harness
        assert client.get(path, headers=AUTH).status_code == 200
        assert all(p == PROJECT for p in store.seen_projects)

    @pytest.mark.parametrize("path", ROUTES)
    def test_project_id_is_never_read_off_the_request(
        self, harness: tuple[TestClient, FakeReportsStore], path: str
    ) -> None:
        client, store = harness
        r = client.get(path, params={"project_id": str(OTHER_PROJECT)}, headers=AUTH)
        assert r.status_code == 200
        assert store.seen_projects != []
        assert all(p == PROJECT for p in store.seen_projects)
        assert str(OTHER_PROJECT) not in r.text

    @pytest.mark.parametrize("path", ROUTES)
    def test_missing_reports_store_is_500_not_an_empty_result(self, path: str) -> None:
        client, _ = _build(None)
        r = client.get(path, headers=AUTH)
        assert r.status_code == 500
        assert r.json() == {"detail": "internal error"}


# --------------------------------------------------------------------------- #
# GET /admin/lift/report
# --------------------------------------------------------------------------- #


def _lift_row(
    *, run: str, arm: Arm, mem_type: MemType | None, outcome_r: float, outcome_code: OutcomeCode = OutcomeCode.INJECTED
) -> LiftRunObservationRow:
    return LiftRunObservationRow(
        run_id=RunId(UUID(run)),
        agent_type_id=AGENT_TYPE,
        arm=arm,
        outcome_code=outcome_code,
        mem_type=mem_type,
        outcome_r=outcome_r,
    )


class TestLiftReport:
    def test_window_is_reported(self, harness: tuple[TestClient, FakeReportsStore]) -> None:
        client, store = harness
        body = client.get("/admin/lift/report", params={"days": 7}, headers=AUTH).json()
        assert body["window"]["days"] == 7
        assert store.last_since == EPOCH - timedelta(days=7)

    def test_cell_below_min_cell_n_is_marked_insufficient_with_real_numbers(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        """5 vs 5 observations: a real bound IS computable, but 5 < killswitch.min_cell_n
        (200), so the cell must say so rather than be dropped or presented as trustworthy."""
        client, store = harness
        rows = []
        for i in range(5):
            rows.append(
                _lift_row(
                    run=f"a0000000-0000-0000-0000-00000000000{i}",
                    arm=Arm.MEMORY_ON,
                    mem_type=MemType.LESSON,
                    outcome_r=0.9,
                )
            )
            rows.append(
                _lift_row(
                    run=f"b0000000-0000-0000-0000-00000000000{i}",
                    arm=Arm.HOLDOUT,
                    mem_type=MemType.LESSON,
                    outcome_r=0.5,
                )
            )
        store.lift_rows = rows
        body = client.get("/admin/lift/report", headers=AUTH).json()
        cells = {c["mem_type"]: c for c in body["cells"]}
        cell = cells["lesson"]
        assert cell["agent_type_id"] == str(AGENT_TYPE)
        assert cell["n_treatment"] == 5
        assert cell["n_control"] == 5
        assert cell["min_cell_n"] == 200
        assert cell["insufficient"] is True
        assert cell["point_estimate"] is not None
        assert cell["lower_bound"] is not None
        assert cell["p_value"] is not None
        # An adjusted p is only readable next to the estimate it adjusts, and this
        # cell's estimate is refused for N -- so no adjusted p comes back either,
        # even though the cell DID enter the correction as a hypothesis.
        assert cell["bh_adjusted_p"] is None
        assert body["methodology"]["bh_hypotheses"] >= 1

    def test_a_truncated_observation_join_says_so_on_the_wire(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        """A join that came back at its cap makes every reported N a LOWER BOUND. If the
        response cannot say that, an operator reads a partial denominator as a total one and
        quotes a lift figure computed from an unknown fraction of the window."""
        client, store = harness
        store.lift_rows = [
            _lift_row(
                run=f"{i:08x}-0000-0000-0000-000000000000",
                arm=Arm.MEMORY_ON if i % 2 == 0 else Arm.HOLDOUT,
                mem_type=MemType.LESSON,
                outcome_r=0.5,
            )
            for i in range(4)
        ]
        body = client.get("/admin/lift/report", headers=AUTH).json()
        assert body["window"]["observations_truncated"] is False
        assert body["window"]["observations_considered"] == 4
        assert body["window"]["observations_cap"] == MAX_LIFT_OBSERVATIONS

        store.lift_rows = store.lift_rows * 1
        store.force_row_count = MAX_LIFT_OBSERVATIONS
        body = client.get("/admin/lift/report", headers=AUTH).json()
        assert body["window"]["observations_truncated"] is True

    def test_methodology_names_where_its_constants_came_from(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        """A dashboard must never have to hard-code PLAN.md's documented defaults and hope
        they match the deployment -- and must never present a process default as this
        project's resolved config either."""
        client, _ = harness
        methodology = client.get("/admin/lift/report", headers=AUTH).json()["methodology"]
        assert methodology["min_cell_n"] == 200
        assert methodology["killswitch_window_days"] == 14
        assert methodology["correction"] == "benjamini-hochberg"
        assert methodology["confidence"] == pytest.approx(0.95)
        assert methodology["bh_alpha"] == pytest.approx(0.05)
        assert methodology["source"] == "process_default"

    def test_cell_with_fewer_than_two_observations_has_no_computable_bound(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, store = harness
        store.lift_rows = [
            _lift_row(
                run="c0000000-0000-0000-0000-000000000001",
                arm=Arm.MEMORY_ON,
                mem_type=MemType.SEMANTIC,
                outcome_r=0.7,
            ),
            _lift_row(
                run="c0000000-0000-0000-0000-000000000002",
                arm=Arm.HOLDOUT,
                mem_type=MemType.SEMANTIC,
                outcome_r=0.6,
            ),
        ]
        body = client.get("/admin/lift/report", headers=AUTH).json()
        cell = next(c for c in body["cells"] if c["mem_type"] == "semantic")
        assert cell["n_treatment"] == 1
        assert cell["n_control"] == 1
        assert cell["insufficient"] is True
        assert cell["point_estimate"] is None
        assert cell["lower_bound"] is None
        assert cell["p_value"] is None

    def test_runs_that_injected_nothing_form_no_cell(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, store = harness
        store.lift_rows = [
            _lift_row(
                run="d0000000-0000-0000-0000-000000000001",
                arm=Arm.MEMORY_ON,
                mem_type=None,
                outcome_r=0.5,
                outcome_code=OutcomeCode.ABSTAINED_THRESHOLD,
            )
        ]
        body = client.get("/admin/lift/report", headers=AUTH).json()
        assert body["cells"] == []

    def test_malformed_observation_is_skipped_not_a_500(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        """`outcome_code=injected` with no `mem_type` breaks `LiftObservation`'s own
        placement invariant -- a data-integrity signal from the write path, not grounds
        to fail the whole report."""
        client, store = harness
        store.lift_rows = [
            _lift_row(
                run="e0000000-0000-0000-0000-000000000001",
                arm=Arm.MEMORY_ON,
                mem_type=None,
                outcome_r=0.5,
                outcome_code=OutcomeCode.INJECTED,
            )
        ]
        r = client.get("/admin/lift/report", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["cells"] == []

    def test_q_trajectory_pagination_is_forwarded_and_bounded(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, store = harness
        store.q_rows = [
            QTrajectoryPointRow(
                memory_id=MEMORY,
                agent_type_id=AGENT_TYPE,
                mem_type=MemType.LESSON,
                q_value=0.7,
                confidence=0.5,
                scored_use_count=3,
                observed_at=EPOCH,
                scoring_epoch_id=2,
            )
        ]
        body = client.get(
            "/admin/lift/report", params={"q_limit": 10, "q_offset": 5}, headers=AUTH
        ).json()
        assert store.last_limit == 10
        assert store.last_offset == 5
        point = body["q_trajectory"]["items"][0]
        assert point["memory_id"] == str(MEMORY)
        assert point["scoring_epoch_id"] == 2
        assert body["q_trajectory"]["limit"] == 10
        assert body["q_trajectory"]["offset"] == 5

        assert client.get("/admin/lift/report", params={"q_limit": 0}, headers=AUTH).status_code == 422
        assert (
            client.get("/admin/lift/report", params={"q_limit": 5000}, headers=AUTH).status_code
            == 422
        )
        assert client.get("/admin/lift/report", params={"days": 0}, headers=AUTH).status_code == 422


class TestBhAdjustedPValues:
    def test_matches_the_standard_step_up_formula(self) -> None:
        adjusted = _bh_adjusted_p_values([0.01, 0.04, 0.03, 0.2])
        assert adjusted[0] == pytest.approx(0.04)
        assert adjusted[1] == pytest.approx(0.05333, abs=1e-4)
        assert adjusted[2] == pytest.approx(0.05333, abs=1e-4)
        assert adjusted[3] == pytest.approx(0.2)

    def test_empty_input_is_empty_output(self) -> None:
        assert _bh_adjusted_p_values([]) == []


# --------------------------------------------------------------------------- #
# GET /admin/staleness/report
# --------------------------------------------------------------------------- #


class TestStalenessReport:
    def test_selector_matches_use_the_real_invalidator_predicate(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, store = harness
        store.invalidation_rows = [
            InvalidationReportRow(
                event_id=UUID("77777777-7777-7777-7777-777777777777"),
                event_type="tool_changed",
                selector={"tool_refs": ["ledger_post"]},
                fired_at=EPOCH,
            )
        ]
        matching_memory = MemoryId(UUID("88888888-8888-8888-8888-888888888888"))
        other_memory = MemoryId(UUID("99999999-9999-9999-9999-999999999999"))
        store.stale_rows = [
            StaleMemoryRow(
                memory_id=matching_memory,
                mem_type=MemType.LESSON,
                strike_count=1,
                status_changed_at=EPOCH,
                last_revalidated_at=None,
                provenance=Provenance(cls=ProvenanceClass.PARSER, tool_refs=("ledger_post",)),
            ),
            StaleMemoryRow(
                memory_id=other_memory,
                mem_type=MemType.LESSON,
                strike_count=1,
                status_changed_at=EPOCH,
                last_revalidated_at=None,
                provenance=Provenance(cls=ProvenanceClass.PARSER, tool_refs=("unrelated_tool",)),
            ),
        ]
        body = client.get("/admin/staleness/report", headers=AUTH).json()
        event = body["invalidation_events"][0]
        matched_ids = {m["memory_id"] for m in event["matched_memories"]}
        assert matched_ids == {str(matching_memory)}
        assert event["matched_memories_total"] == 1
        assert event["matched_memories_truncated"] is False

    def test_a_selector_naming_nothing_indexed_matches_nothing(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        """The candidate index narrows which memories `selector_matches` is asked about; it
        must never narrow to a DIFFERENT answer. A selector whose tool_ref no stale memory
        carries has to come back empty, not fall through to matching everything."""
        client, store = harness
        store.invalidation_rows = [
            InvalidationReportRow(
                event_id=UUID("77777777-7777-7777-7777-777777777777"),
                event_type="tool_changed",
                selector={"tool_refs": ["never_referenced"]},
                fired_at=EPOCH,
            )
        ]
        store.stale_rows = [
            StaleMemoryRow(
                memory_id=MemoryId(UUID("88888888-8888-8888-8888-888888888888")),
                mem_type=MemType.LESSON,
                strike_count=1,
                status_changed_at=EPOCH,
                last_revalidated_at=None,
                provenance=Provenance(cls=ProvenanceClass.PARSER, tool_refs=("ledger_post",)),
            )
        ]
        body = client.get("/admin/staleness/report", headers=AUTH).json()
        assert body["invalidation_events"][0]["matched_memories"] == []

    def test_trace_id_and_input_sig_selectors_also_match(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        """All three provenance channels `selector_matches` reads must survive the index --
        an index built over tool_refs alone would silently drop trace-scoped invalidations."""
        client, store = harness
        by_trace = MemoryId(UUID("aaaaaaaa-0000-0000-0000-000000000001"))
        by_sig = MemoryId(UUID("aaaaaaaa-0000-0000-0000-000000000002"))
        run = RunId(UUID("bbbbbbbb-0000-0000-0000-000000000001"))
        store.invalidation_rows = [
            InvalidationReportRow(
                event_id=UUID("77777777-7777-7777-7777-777777777777"),
                event_type="trace_changed",
                selector={"trace_ids": [str(run)], "input_sig_hashes": ["ab12"]},
                fired_at=EPOCH,
            )
        ]
        store.stale_rows = [
            StaleMemoryRow(
                memory_id=by_trace,
                mem_type=MemType.LESSON,
                strike_count=1,
                status_changed_at=EPOCH,
                last_revalidated_at=None,
                provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run,)),
            ),
            StaleMemoryRow(
                memory_id=by_sig,
                mem_type=MemType.SEMANTIC,
                strike_count=1,
                status_changed_at=EPOCH,
                last_revalidated_at=None,
                provenance=Provenance(
                    cls=ProvenanceClass.PARSER, input_sig_hashes=(bytes.fromhex("ab12"),)
                ),
            ),
        ]
        body = client.get("/admin/staleness/report", headers=AUTH).json()
        matched = {m["memory_id"] for m in body["invalidation_events"][0]["matched_memories"]}
        assert matched == {str(by_trace), str(by_sig)}

    def test_a_wide_match_set_is_capped_but_its_count_stays_exact(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        """An over-matching selector is the failure an operator is looking for, so the COUNT
        must stay exact even when the row list is capped -- reporting the capped length as the
        count would understate the exact problem the number exists to reveal."""
        client, store = harness
        store.invalidation_rows = [
            InvalidationReportRow(
                event_id=UUID("77777777-7777-7777-7777-777777777777"),
                event_type="tool_changed",
                selector={"tool_refs": ["over_matching"]},
                fired_at=EPOCH,
            )
        ]
        store.stale_rows = [
            StaleMemoryRow(
                memory_id=MemoryId(UUID(f"aaaaaaaa-0000-0000-0000-{i:012d}")),
                mem_type=MemType.LESSON,
                strike_count=1,
                status_changed_at=EPOCH,
                last_revalidated_at=None,
                provenance=Provenance(
                    cls=ProvenanceClass.PARSER, tool_refs=("over_matching",)
                ),
            )
            for i in range(200)
        ]
        event = client.get("/admin/staleness/report", headers=AUTH).json()[
            "invalidation_events"
        ][0]
        assert event["matched_memories_total"] == 200
        assert len(event["matched_memories"]) < 200
        assert event["matched_memories_truncated"] is True

    def test_approaching_revalidation_carries_r_days_and_age(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, store = harness
        store.revalidation_rows = [
            RevalidationCandidateRow(
                memory_id=MEMORY,
                mem_type=MemType.PREFERENCE,
                reference_at=EPOCH - timedelta(days=25),
                age_days=25.0,
                last_revalidated_at=None,
            )
        ]
        body = client.get(
            "/admin/staleness/report", params={"r_days": 30}, headers=AUTH
        ).json()
        candidate = body["approaching_revalidation"][0]
        assert candidate["memory_id"] == str(MEMORY)
        assert candidate["r_days"] == 30
        assert candidate["age_days"] == pytest.approx(25.0)
        assert body["r_days"] == 30

    def test_r_days_defaults_to_the_lifecycle_config_default(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, _ = harness
        body = client.get("/admin/staleness/report", headers=AUTH).json()
        assert body["r_days"] == 30

    def test_event_pagination_is_bounded(self, harness: tuple[TestClient, FakeReportsStore]) -> None:
        client, store = harness
        assert (
            client.get(
                "/admin/staleness/report", params={"event_limit": 0}, headers=AUTH
            ).status_code
            == 422
        )
        assert (
            client.get(
                "/admin/staleness/report", params={"event_limit": 5000}, headers=AUTH
            ).status_code
            == 422
        )
        assert (
            client.get(
                "/admin/staleness/report", params={"approaching_offset": -1}, headers=AUTH
            ).status_code
            == 422
        )
        assert store.seen_projects == []


# --------------------------------------------------------------------------- #
# GET /admin/consolidation/diffs
# --------------------------------------------------------------------------- #


class TestConsolidationDiffs:
    def test_empty_is_a_valid_body_not_an_error(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, _ = harness
        body = client.get("/admin/consolidation/diffs", headers=AUTH).json()
        assert body == {
            "items": [],
            "limit": 100,
            "offset": 0,
            "returned": 0,
            # Constant `false` on this build: no writer for `workers.consolidator`'s
            # per-sweep DeltaRecords exists, so "this project ran no sweeps" and "nothing
            # in this system records sweeps" must not render identically.
            "sweep_deltas_available": False,
        }

    def test_value_retained_fraction_is_derived_from_delta_pct(
        self, harness: tuple[TestClient, FakeReportsStore]
    ) -> None:
        client, store = harness
        store.consolidation_rows = [
            ConsolidationDiffRow(
                agent_type_id=AGENT_TYPE,
                key="baseline:latency_ms",
                version=3,
                value={"v": 120.0},
                delta_pct=8.0,
                clamped=False,
                computed_at=EPOCH,
            ),
            ConsolidationDiffRow(
                agent_type_id=AGENT_TYPE,
                key="baseline:no_delta",
                version=1,
                value={"v": 1.0},
                delta_pct=None,
                clamped=False,
                computed_at=EPOCH,
            ),
        ]
        body = client.get("/admin/consolidation/diffs", headers=AUTH).json()
        by_key = {i["key"]: i for i in body["items"]}
        assert by_key["baseline:latency_ms"]["value_retained_fraction"] == pytest.approx(0.92)
        assert by_key["baseline:no_delta"]["value_retained_fraction"] is None
        # The field must NOT be named for the harness's ACE brevity-bias metric --
        # this number is derived-state movement, not surviving facts.
        assert "information_retention" not in by_key["baseline:latency_ms"]

    def test_pagination_is_bounded(self, harness: tuple[TestClient, FakeReportsStore]) -> None:
        client, store = harness
        assert (
            client.get("/admin/consolidation/diffs", params={"limit": 0}, headers=AUTH).status_code
            == 422
        )
        assert (
            client.get(
                "/admin/consolidation/diffs", params={"limit": 5000}, headers=AUTH
            ).status_code
            == 422
        )
        assert store.seen_projects == []


# --------------------------------------------------------------------------- #
# GET /admin/injections
# --------------------------------------------------------------------------- #


class TestInjections:
    def test_feed_is_joinable_to_memory_ids(self, harness: tuple[TestClient, FakeReportsStore]) -> None:
        client, store = harness
        store.injection_rows = [
            InjectionFeedRow(
                run_id=RunId(UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                memory_id=MEMORY,
                slot="fact",
                score=0.42,
                tokens=17,
                injected_at=EPOCH,
            )
        ]
        body = client.get("/admin/injections", headers=AUTH).json()
        assert body["items"][0]["memory_id"] == str(MEMORY)
        assert body["items"][0]["slot"] == "fact"
        assert body["returned"] == 1

    def test_pagination_is_bounded(self, harness: tuple[TestClient, FakeReportsStore]) -> None:
        client, store = harness
        assert client.get("/admin/injections", params={"limit": 0}, headers=AUTH).status_code == 422
        assert (
            client.get("/admin/injections", params={"limit": 5000}, headers=AUTH).status_code == 422
        )
        assert client.get("/admin/injections", params={"offset": -1}, headers=AUTH).status_code == 422
        assert store.seen_projects == []
