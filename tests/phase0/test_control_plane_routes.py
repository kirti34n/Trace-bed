"""The control-plane read routes (D-093): `/admin/whoami`, `/admin/memory`,
`/admin/review_queue`, `/admin/killswitch_state`, `/admin/invalidations`,
`/admin/spend`, `/admin/config`.

Fully offline via `TestClient` + fake `AppDeps` (contract §12), the same shape
`test_admin_routes.py` uses for the registry-write plane. What these tests are
actually for:

1. **Invariant 4 by construction.** Every route here is `ScopeDep`-authenticated
   and passes `scope.project_id` — never a value off the request — to the
   reader. `test_project_id_is_never_read_off_the_request` proves it by handing
   a `project_id` query parameter and asserting the reader still received the
   scope's project, and that the (extra, unmodelled) parameter changed nothing.
   `test_unauthenticated_is_401_before_any_read` proves the reader is not even
   reached without a credential — a route that read first and authorised second
   would still pass a naive status-code assertion.

2. **Fail-closed on a missing reader.** `control_plane=None` (a deployment that
   wired no reader) must be a 500, not an empty list. An empty list renders on
   the dashboard as "this project has no review items / no kill-switch
   decisions", which is a governance claim the server has not made.

3. **The enum filter is a filter, not a suggestion.** `?status=nonsense` is a
   422, not "matched nothing" — the two are indistinguishable on screen and
   only one of them means the vault is clean.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tracebed.adapters.identity import Principal
from tracebed.api.deps import AppDeps
from tracebed.api.main import create_app
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import AuthConfig, EmbeddingConfig, StorageConfig, TracebedSettings
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import AuthenticationFailed, NotFound
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId
from tracebed.domain.memory import Provenance
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.rows import (
    InvalidationEventRow,
    KillswitchStateRow,
    MemoryItemRow,
    ReviewQueueRow,
    SpendRow,
)

pytestmark = pytest.mark.phase0

EPOCH = datetime(2026, 3, 15, 12, 0, tzinfo=UTC)

PROJECT = ProjectId(UUID("11111111-1111-1111-1111-111111111111"))
OTHER_PROJECT = ProjectId(UUID("22222222-2222-2222-2222-222222222222"))
AGENT_TYPE = AgentTypeId(UUID("33333333-3333-3333-3333-333333333333"))
PRINCIPAL = PrincipalId(UUID("44444444-4444-4444-4444-444444444444"))
MEMORY = MemoryId(UUID("55555555-5555-5555-5555-555555555555"))


# --------------------------------------------------------------------------- #
# Fakes.
# --------------------------------------------------------------------------- #


class _AuthenticatesVerifier:
    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        if not authorization and not api_key:
            raise AuthenticationFailed("no credential presented")
        return Principal(principal_id=PRINCIPAL, kind="api_key", external_ref="ref")


class _Resolver:
    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        return ProjectScope(
            project_id=PROJECT, agent_type_id=AGENT_TYPE, principal_id=principal_id
        )


class _NeverCalledQueue:
    def enqueue(self, *args: object, **kwargs: object) -> int:
        raise AssertionError("no control-plane read route enqueues")


class _NeverCalledTelemetry:
    def record_retrieval(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("no control-plane read route records telemetry")


class _NeverCalledAdmin:
    def create_project(self, *args: object, **kwargs: object) -> ProjectId:
        raise AssertionError("no control-plane read route writes the registry")

    def create_agent_registration(
        self, *args: object, **kwargs: object
    ) -> tuple[PrincipalId, AgentTypeId]:
        raise AssertionError("no control-plane read route writes the registry")


class _Stubs:
    """Ports the control-plane routes never touch, but `AppDeps` requires."""

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> MemoryItemRow:
        raise NotFound("not found")

    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]:
        return iter(())

    def insert_invalidation_event(self, *args: object, **kwargs: object) -> UUID:
        raise AssertionError("no read route writes")

    def create_project_partitions(self, project_id: ProjectId) -> None:
        raise AssertionError("no read route provisions partitions")

    def ensure_project_kek(self, project_id: ProjectId) -> None:
        raise AssertionError("no read route provisions keys")


def _memory_row(status: Status = Status.VALIDATED) -> MemoryItemRow:
    return MemoryItemRow(
        id=MEMORY,
        project_id=PROJECT,
        scope_type=ScopeType.AGENT_TYPE,
        scope_id=AGENT_TYPE.value,
        mem_type=MemType.LESSON,
        kind="tool_failure",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.A,
        status=status,
        content="retry ledger_post with an idempotency key after a 503",
        content_hash="ab" * 32,
        token_count=11,
        subject_tag=None,
        q_value=0.81,
        confidence=0.9,
        scored_use_count=12,
        strike_count=0,
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=()),
        scan_verdict_id=uuid4(),
        schema_version=1,
        created_at=EPOCH,
        status_changed_at=EPOCH,
    )


@dataclass
class FakeControlPlane:
    """Records the project id every method was handed — the assertion that
    matters is not "a row came back" but "the row came back for the SCOPE'S
    project", which is the only thing standing between this route set and
    leak-suite probe 3."""

    seen_projects: list[ProjectId] = field(default_factory=list)
    memories: list[MemoryItemRow] = field(default_factory=list)
    review_items: list[ReviewQueueRow] = field(default_factory=list)
    killswitch: list[KillswitchStateRow] = field(default_factory=list)
    invalidations: list[InvalidationEventRow] = field(default_factory=list)
    spend: list[SpendRow] = field(default_factory=list)
    project_cfg: dict[str, object] = field(default_factory=dict)
    agent_cfg: dict[str, object] = field(default_factory=dict)
    last_statuses: Sequence[Status] | None = None
    last_limit: int | None = None
    last_include_resolved: bool | None = None
    last_since: date | None = None
    last_agent_type: AgentTypeId | None = None

    def list_memories(
        self,
        project_id: ProjectId,
        *,
        statuses: Sequence[Status] | None = None,
        limit: int = 100,
    ) -> list[MemoryItemRow]:
        self.seen_projects.append(project_id)
        self.last_statuses = statuses
        self.last_limit = limit
        return list(self.memories)

    def list_review_items(
        self, project_id: ProjectId, *, include_resolved: bool = False, limit: int = 100
    ) -> list[ReviewQueueRow]:
        self.seen_projects.append(project_id)
        self.last_include_resolved = include_resolved
        self.last_limit = limit
        return list(self.review_items)

    def list_killswitch_state(self, project_id: ProjectId) -> list[KillswitchStateRow]:
        self.seen_projects.append(project_id)
        return list(self.killswitch)

    def list_invalidation_events(
        self, project_id: ProjectId, *, limit: int = 100
    ) -> list[InvalidationEventRow]:
        self.seen_projects.append(project_id)
        self.last_limit = limit
        return list(self.invalidations)

    def spend_since(self, project_id: ProjectId, since: date) -> list[SpendRow]:
        self.seen_projects.append(project_id)
        self.last_since = since
        return list(self.spend)

    def get_project_config(self, project_id: ProjectId) -> Mapping[str, object]:
        self.seen_projects.append(project_id)
        return dict(self.project_cfg)

    def get_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> Mapping[str, object]:
        self.seen_projects.append(project_id)
        self.last_agent_type = agent_type_id
        return dict(self.agent_cfg)


def _build(control_plane: Any) -> tuple[TestClient, FakeControlPlane | None]:
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
        control_plane=control_plane,
    )
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
        embedding=EmbeddingConfig(model_version="test"),
        auth=AuthConfig(admin_key_env="TB_TEST_UNUSED_ADMIN_KEY"),
    )
    return TestClient(create_app(settings, deps)), control_plane


AUTH = {"x-api-key": "a-valid-tenant-key"}

ROUTES = [
    "/admin/whoami",
    "/admin/memory",
    "/admin/review_queue",
    "/admin/killswitch_state",
    "/admin/invalidations",
    "/admin/spend",
    "/admin/config",
]


@pytest.fixture
def harness() -> tuple[TestClient, FakeControlPlane]:
    cp = FakeControlPlane()
    client, _ = _build(cp)
    return client, cp


# --------------------------------------------------------------------------- #
# Auth + isolation.
# --------------------------------------------------------------------------- #


class TestAuthAndIsolation:
    @pytest.mark.parametrize("path", ROUTES)
    def test_unauthenticated_is_401_before_any_read(
        self, harness: tuple[TestClient, FakeControlPlane], path: str
    ) -> None:
        client, cp = harness
        assert client.get(path).status_code == 401
        # Not merely "the response was 401": the reader was never reached, so
        # there is no path on which a row is fetched and then discarded.
        assert cp.seen_projects == []

    @pytest.mark.parametrize("path", ROUTES)
    def test_authenticated_reads_use_the_derived_scope(
        self, harness: tuple[TestClient, FakeControlPlane], path: str
    ) -> None:
        client, cp = harness
        assert client.get(path, headers=AUTH).status_code == 200
        assert all(p == PROJECT for p in cp.seen_projects)

    @pytest.mark.parametrize(
        "path", ["/admin/memory", "/admin/review_queue", "/admin/spend", "/admin/config"]
    )
    def test_project_id_is_never_read_off_the_request(
        self, harness: tuple[TestClient, FakeControlPlane], path: str
    ) -> None:
        """A caller naming another project must change nothing at all —
        neither the scope the reader is handed nor the response."""
        client, cp = harness
        r = client.get(path, params={"project_id": str(OTHER_PROJECT)}, headers=AUTH)
        assert r.status_code == 200
        assert cp.seen_projects != []
        assert all(p == PROJECT for p in cp.seen_projects)
        assert OTHER_PROJECT.value.hex not in r.text
        assert str(OTHER_PROJECT) not in r.text

    @pytest.mark.parametrize("path", ROUTES)
    def test_no_admin_key_is_required_and_none_grants_extra_scope(self, path: str) -> None:
        """These are ordinary project-scoped reads, not the registry-write
        plane: presenting the bootstrap admin key must not widen anything."""
        cp = FakeControlPlane()
        client, _ = _build(cp)
        r = client.get(path, headers={**AUTH, "x-admin-key": "whatever"})
        assert r.status_code == 200
        assert all(p == PROJECT for p in cp.seen_projects)


class TestFailsClosedWithoutAReader:
    @pytest.mark.parametrize("path", [p for p in ROUTES if p != "/admin/whoami"])
    def test_missing_control_plane_is_500_not_an_empty_result(self, path: str) -> None:
        client, _ = _build(None)
        r = client.get(path, headers=AUTH)
        assert r.status_code == 500
        assert r.json() == {"detail": "internal error"}

    def test_whoami_needs_no_reader(self) -> None:
        """`/admin/whoami` reports the scope the dependency chain already
        derived; it touches no table, so it must keep working on a deployment
        with no control-plane reader at all."""
        client, _ = _build(None)
        assert client.get("/admin/whoami", headers=AUTH).status_code == 200


# --------------------------------------------------------------------------- #
# Per-route bodies.
# --------------------------------------------------------------------------- #


class TestWhoami:
    def test_reports_the_server_derived_scope(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, _ = harness
        body = client.get("/admin/whoami", headers=AUTH).json()
        assert body == {
            "project_id": str(PROJECT),
            "agent_type_id": str(AGENT_TYPE),
            "principal_id": str(PRINCIPAL),
        }


class TestMemoryList:
    def test_returns_rows_with_the_limit_it_applied(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        cp.memories = [_memory_row()]
        body = client.get("/admin/memory", headers=AUTH).json()
        assert body["returned"] == 1
        assert body["limit"] == 100
        assert body["items"][0]["id"] == str(MEMORY)
        assert body["items"][0]["status"] == "validated"

    def test_status_filter_is_passed_through_as_enum_members(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        r = client.get(
            "/admin/memory", params=[("status", "quarantined"), ("status", "stale")], headers=AUTH
        )
        assert r.status_code == 200
        assert cp.last_statuses == [Status.QUARANTINED, Status.STALE]

    def test_unknown_status_is_422_not_an_empty_match(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        assert client.get("/admin/memory", params={"status": "nonsense"}, headers=AUTH).status_code == 422
        assert cp.seen_projects == []

    def test_limit_is_bounded_at_the_wire(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        assert client.get("/admin/memory", params={"limit": 5000}, headers=AUTH).status_code == 422
        assert client.get("/admin/memory", params={"limit": 0}, headers=AUTH).status_code == 422
        assert cp.seen_projects == []


class TestReviewQueue:
    def test_open_items_only_by_default(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        cp.review_items = [
            ReviewQueueRow(
                item_id=UUID("66666666-6666-6666-6666-666666666666"),
                reason="retirement_below_k_principals",
                memory_id=MEMORY,
                opened_at=EPOCH,
                resolved_at=None,
                resolution=None,
            )
        ]
        body = client.get("/admin/review_queue", headers=AUTH).json()
        assert cp.last_include_resolved is False
        assert body["include_resolved"] is False
        assert body["items"][0]["memory_id"] == str(MEMORY)
        assert body["items"][0]["resolved_at"] is None

    def test_include_resolved_is_forwarded(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        client.get("/admin/review_queue", params={"include_resolved": "true"}, headers=AUTH)
        assert cp.last_include_resolved is True


class TestKillswitchState:
    def test_empty_is_a_valid_body_not_an_error(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, _ = harness
        assert client.get("/admin/killswitch_state", headers=AUTH).json() == {"cells": []}

    def test_null_agent_type_is_preserved_as_the_project_wide_overlay(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        cp.killswitch = [
            KillswitchStateRow(
                agent_type_id=None,
                mem_type=MemType.SEMANTIC,
                disabled=True,
                evidence={"source": "auto_killswitch", "lift_ci_low": -0.08, "n": 412},
                changed_at=EPOCH,
            )
        ]
        cell = client.get("/admin/killswitch_state", headers=AUTH).json()["cells"][0]
        assert cell["agent_type_id"] is None
        assert cell["disabled"] is True
        # Verbatim, not reshaped: the worker owns this record's meaning.
        assert cell["evidence"] == {"source": "auto_killswitch", "lift_ci_low": -0.08, "n": 412}

    def test_there_is_no_write_route(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        """PLAN.md §10: no admin bypass exists in code. A dashboard that could
        POST here would be exactly that bypass."""
        client, _ = harness
        r = client.post("/admin/killswitch_state", headers=AUTH, json={"disabled": False})
        assert r.status_code == 405


class TestInvalidations:
    def test_selector_round_trips(self, harness: tuple[TestClient, FakeControlPlane]) -> None:
        client, cp = harness
        cp.invalidations = [
            InvalidationEventRow(
                event_id=UUID("77777777-7777-7777-7777-777777777777"),
                event_type="cache_flush",
                selector={"tool_id": "ledger_post"},
                fired_at=EPOCH,
            )
        ]
        body = client.get("/admin/invalidations", headers=AUTH).json()
        assert body["returned"] == 1
        assert body["events"][0]["selector"] == {"tool_id": "ledger_post"}


class TestSpend:
    def test_window_is_reported_with_the_rows(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        cp.spend = [
            SpendRow(
                day=date(2026, 3, 15),
                worker="distiller",
                model_id="gemini-3.1-pro",
                tokens_in=1200,
                tokens_out=300,
                cost_usd=0.42,
            )
        ]
        body = client.get("/admin/spend", params={"days": 7}, headers=AUTH).json()
        assert body["days"] == 7
        # 7 days INCLUSIVE of the clock's own day: a window reported as 7 days
        # that actually covered 8 would overstate every per-day average drawn
        # from it.
        assert body["since"] == "2026-03-09"
        assert cp.last_since == date(2026, 3, 9)
        assert body["cells"][0]["cost_usd"] == pytest.approx(0.42)

    def test_days_is_bounded(self, harness: tuple[TestClient, FakeControlPlane]) -> None:
        client, cp = harness
        assert client.get("/admin/spend", params={"days": 0}, headers=AUTH).status_code == 422
        assert client.get("/admin/spend", params={"days": 10_000}, headers=AUTH).status_code == 422
        assert cp.seen_projects == []


class TestConfig:
    def test_reports_both_override_layers_for_the_derived_agent_type(
        self, harness: tuple[TestClient, FakeControlPlane]
    ) -> None:
        client, cp = harness
        cp.project_cfg = {"retrieval.total_budget_ms": 300}
        cp.agent_cfg = {"retrieval.total_budget_ms": 260}
        body = client.get("/admin/config", headers=AUTH).json()
        assert body["agent_type_id"] == str(AGENT_TYPE)
        assert body["project"] == {"retrieval.total_budget_ms": 300}
        assert body["agent_type"] == {"retrieval.total_budget_ms": 260}
        # The agent type read is the SCOPE'S, never one a caller could name.
        assert cp.last_agent_type == AGENT_TYPE
