"""Server-side scope derivation over `/v1/*` and `GET /admin/memory/{id}`
(PHASE0-CONTRACT.md §9.2/§9.3, invariant 4).

Fully offline: `TestClient(create_app(settings, AppDeps(...fakes...)))`, no
Postgres/Valkey/S3 (contract §12). Proves: no credential -> 401; a valid API
key resolves `ProjectScope` from the fake registry; a body carrying
`project_id` -> 422 (no route model declares the field, and every model
forbids extras); a feedback body carrying `weight` -> 422; `/v1/retrieve`
returns a UUIDv7 `run_id`, the exact `MEMORY_HEADER`, and `append_last`
placement; every enqueue-only route 202s and enqueues the exact §9.5
envelope shape; a cross-project by-id fetch is byte-identical to a
genuinely-absent one (leak-suite probe 2, asserted on the response BODY, not
just the status).
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tracebed.adapters.identity import Principal
from tracebed.api.deps import AppDeps
from tracebed.api.main import create_app
from tracebed.api.models import MAX_QUERY_TEXT_CHARS, MAX_SEQ
from tracebed.domain.canonical import content_hash
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EmbeddingConfig, StorageConfig, TracebedSettings
from tracebed.domain.enums import (
    Arm,
    Lane,
    MemType,
    OutcomeCode,
    ProvenanceClass,
    ScopeType,
    TrustTier,
)
from tracebed.domain.errors import AuthenticationFailed, NotFound
from tracebed.domain.events import MEMORY_HEADER, PLACEMENT_APPEND_LAST
from tracebed.domain.ids import (
    AgentTypeId,
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    uuid7_timestamp_ms,
)
from tracebed.domain.memory import Provenance
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.rows import MemoryItemRow

pytestmark = pytest.mark.phase0


# --------------------------------------------------------------------------- #
# Fakes — chunk-local (contract §13.1: harness's shared fixtures cover
# fixture *names*, not chunk-specific fake implementations).
# --------------------------------------------------------------------------- #


@dataclass
class FakeQueue:
    items: list[tuple[str, ProjectId, Mapping[str, Any]]] = field(default_factory=list)

    def enqueue(
        self,
        topic: str,
        project_id: ProjectId,
        payload: Mapping[str, object],
        priority: int = 100,
        available_at: datetime | None = None,
    ) -> int:
        del priority, available_at
        self.items.append((topic, project_id, payload))
        return len(self.items)


@dataclass
class FakeTelemetry:
    calls: list[dict[str, object]] = field(default_factory=list)

    def record_retrieval(
        self,
        project_id: ProjectId,
        run_id: object,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None:
        self.calls.append(
            {
                "project_id": project_id,
                "run_id": run_id,
                "outcome_code": outcome_code,
                "latency_ms": latency_ms,
                "embed_latency_ms": embed_latency_ms,
                "candidates_considered": candidates_considered,
                "top_score": top_score,
                "arm": arm,
            }
        )


class FakeMemoryReader:
    """A rows-by-(project, id) store that behaves exactly like
    `Repo.get_memory_by_id` (contract §5.1): a row is returned only when BOTH
    the project and the id match, and every other case — absent id, or an id
    that exists under a different project — raises the same `NotFound`.

    Holding real rows is the point. A fake that raised unconditionally would
    make `TestUniform404` pass no matter what the route did with
    `scope.project_id`, including passing a caller-supplied one; with rows
    present, the cross-project probe only 404s because the route scoped the
    read to the authenticated principal's project.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[ProjectId, UUID], Any] = {}

    def put(self, project_id: ProjectId, memory_id: UUID, row: Any) -> None:
        self.rows[(project_id, memory_id)] = row

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> Any:
        row = self.rows.get((project_id, memory_id.value))
        if row is None:
            # Deliberately a *distinguishing* message: if `api/main.py`'s 404
            # handler ever derived its body from the exception instead of
            # emitting the fixed §9.4 string, the two ids in
            # `test_cross_project_and_absent_memory_are_byte_identical` would
            # produce different bytes and that test would go red.
            raise NotFound(f"no memory {memory_id} in project {project_id}")
        return row


class FakeExporter:
    """Yields rows only for the project asked for — an export handed the wrong
    project id yields nothing, so a route that stopped using `scope.project_id`
    turns `test_export_project_streams_ndjson_scoped_to_caller` red."""

    def __init__(self, project_id: ProjectId) -> None:
        self._project_id = project_id

    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]:
        if project_id != self._project_id:
            return
        yield {"table": "memory_item", "row": {"project_id": str(project_id)}}


class FakeAdmin:
    def create_project(
        self, name: str, retention_policy: Mapping[str, object] | None = None
    ) -> ProjectId:
        del name, retention_policy
        return ProjectId(uuid4())

    def create_agent_type(self, project_id: ProjectId, name: str) -> AgentTypeId:
        del project_id, name
        return AgentTypeId(uuid4())

    def register_agent(
        self, project_id: ProjectId, principal_id: PrincipalId, agent_type_id: AgentTypeId
    ) -> None:
        del project_id, principal_id, agent_type_id

    def create_principal(self, kind: str, external_ref: str, key_hash: str | None) -> PrincipalId:
        del kind, external_ref, key_hash
        return PrincipalId(uuid4())


class FakePartitions:
    def create_project_partitions(self, project_id: ProjectId) -> None:
        del project_id


class FakeKeys:
    def ensure_project_kek(self, project_id: ProjectId) -> None:
        del project_id


@dataclass
class FakeVerifier:
    """`api_key == "good"` authenticates as one fixed principal; anything
    else fails — enough surface for the scope-derivation tests, which are
    not re-proving `ApiKeyVerifier` itself (that is `test_auth.py`'s job)."""

    principal_id: PrincipalId

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        del authorization
        if api_key == "good":
            return Principal(principal_id=self.principal_id, kind="api_key", external_ref="k1")
        raise AuthenticationFailed("bad credential")


@dataclass
class FakeResolver:
    scope: ProjectScope

    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        del principal_id
        return self.scope


def _settings() -> TracebedSettings:
    return TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
        embedding=EmbeddingConfig(model_version="test"),
    )


@dataclass
class FakeInvalidations:
    """`AppDeps.invalidations` (C-31). Records `(project_id, event_type, selector)`
    so `TestInvalidation` can prove the route wrote the caller's OWN project id
    and the body it was handed — as merged the route returned 202 while
    discarding the event entirely, which no wire-level assertion could catch."""

    rows: list[tuple[ProjectId, str, Mapping[str, Any] | None]] = field(default_factory=list)

    def insert_invalidation_event(
        self,
        project_id: ProjectId,
        event_type: str,
        selector: Mapping[str, Any] | None = None,
    ) -> UUID:
        self.rows.append((project_id, event_type, selector))
        return uuid4()


@dataclass
class Harness:
    client: TestClient
    queue: FakeQueue
    telemetry: FakeTelemetry
    memory: FakeMemoryReader
    invalidations: FakeInvalidations


def _client(
    *, scope: ProjectScope, queue: FakeQueue | None = None, telemetry: FakeTelemetry | None = None
) -> Harness:
    queue = queue if queue is not None else FakeQueue()
    telemetry = telemetry if telemetry is not None else FakeTelemetry()
    memory = FakeMemoryReader()
    invalidations = FakeInvalidations()
    deps = AppDeps(
        verifier=FakeVerifier(principal_id=scope.principal_id),
        resolver=FakeResolver(scope=scope),
        queue=queue,
        telemetry=telemetry,
        memory_reader=memory,
        exporter=FakeExporter(scope.project_id),
        invalidations=invalidations,
        admin=FakeAdmin(),
        partitions=FakePartitions(),
        keys=FakeKeys(),
        clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
    )
    app = create_app(_settings(), deps)
    return Harness(
        client=TestClient(app, raise_server_exceptions=True),
        queue=queue,
        telemetry=telemetry,
        memory=memory,
        invalidations=invalidations,
    )


@pytest.fixture
def scope() -> ProjectScope:
    return ProjectScope(
        project_id=ProjectId(uuid4()), agent_type_id=AgentTypeId(uuid4()), principal_id=PrincipalId(uuid4())
    )


_RUN_CTX = {"query_text": "how do I configure X?"}


# --------------------------------------------------------------------------- #
# Auth + scope derivation.
# --------------------------------------------------------------------------- #


class TestAuthAndScope:
    def test_no_credential_is_401(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        r = client.post("/v1/retrieve", json={"agent_type": "a", "run_ctx": _RUN_CTX})
        assert r.status_code == 401
        assert r.json() == {"detail": "authentication failed"}

    def test_bad_key_is_401(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        r = client.post(
            "/v1/retrieve",
            headers={"x-api-key": "wrong"},
            json={"agent_type": "a", "run_ctx": _RUN_CTX},
        )
        assert r.status_code == 401

    def test_valid_key_resolves_scope_from_the_registry(self, scope: ProjectScope) -> None:
        """Not directly observable from the response body (the stub never
        echoes scope) — proven indirectly via `FakeTelemetry`, which only
        `record_retrieval` writes to, always keyed by `scope.project_id`."""
        h = _client(scope=scope)
        client, telemetry = h.client, h.telemetry
        r = client.post(
            "/v1/retrieve",
            headers={"x-api-key": "good"},
            json={"agent_type": "a", "run_ctx": _RUN_CTX},
        )
        assert r.status_code == 200
        assert telemetry.calls[0]["project_id"] == scope.project_id


# --------------------------------------------------------------------------- #
# extra="forbid" -> 422 (invariant 4 for project_id, invariant 8 for weight).
# --------------------------------------------------------------------------- #


class TestNoSmuggledFields:
    def test_project_id_in_retrieve_body_is_422(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        r = client.post(
            "/v1/retrieve",
            headers={"x-api-key": "good"},
            json={
                "agent_type": "a",
                "run_ctx": _RUN_CTX,
                "project_id": str(uuid4()),
            },
        )
        assert r.status_code == 422

    def test_project_id_in_trace_body_is_422(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        r = client.post(
            "/v1/trace",
            headers={"x-api-key": "good"},
            json={
                "run_id": str(uuid4()),
                "seq": 0,
                "event": {"type": "run_start", "ts": "2026-01-01T00:00:00Z"},
                "project_id": str(uuid4()),
            },
        )
        assert r.status_code == 422

    def test_weight_in_feedback_body_is_422(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        r = client.post(
            "/v1/feedback",
            headers={"x-api-key": "good"},
            json={
                "run_id": str(uuid4()),
                "event": {
                    "adapter": "verdict",
                    "outcome": "positive",
                    "event_id": str(uuid4()),
                    "weight": 1.0,
                },
            },
        )
        assert r.status_code == 422


# --------------------------------------------------------------------------- #
# /v1/retrieve stub shape (contract §9.3, Task 16).
# --------------------------------------------------------------------------- #


class TestRetrieveStub:
    def test_shape_uuid7_header_placement(self, scope: ProjectScope) -> None:
        h = _client(scope=scope)
        client, telemetry = h.client, h.telemetry
        r = client.post(
            "/v1/retrieve",
            headers={"x-api-key": "good"},
            json={"agent_type": "a", "run_ctx": _RUN_CTX},
        )
        assert r.status_code == 200
        body = r.json()

        run_id = UUID(body["run_id"])
        assert run_id.version == 7
        uuid7_timestamp_ms(run_id)  # raises on a non-v7 id; the assertion is that it does not

        assert body["run_id_origin"] == "server"
        assert body["arm"] == "memory_on"
        assert body["outcome_code"] == "empty_result"

        context_block = body["context_block"]
        assert context_block["header"] == MEMORY_HEADER
        assert context_block["placement"] == PLACEMENT_APPEND_LAST
        assert context_block["slots"] == []
        assert context_block["rendered"] == ""

        # Every retrieval writes a telemetry row, including empty ones
        # (contract §8's TelemetryPort docstring).
        assert len(telemetry.calls) == 1
        assert telemetry.calls[0]["outcome_code"] == OutcomeCode.EMPTY_RESULT
        assert telemetry.calls[0]["arm"] == Arm.MEMORY_ON

    def test_two_calls_mint_distinct_run_ids(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        body = {"agent_type": "a", "run_ctx": _RUN_CTX}
        r1 = client.post("/v1/retrieve", headers={"x-api-key": "good"}, json=body)
        r2 = client.post("/v1/retrieve", headers={"x-api-key": "good"}, json=body)
        assert r1.json()["run_id"] != r2.json()["run_id"]


# --------------------------------------------------------------------------- #
# Enqueue-only routes: 202 + the exact §9.5 envelope, scope ids server-side.
# --------------------------------------------------------------------------- #


class TestEnqueueRoutes:
    def test_trace_enqueues_the_exact_envelope(self, scope: ProjectScope) -> None:
        h = _client(scope=scope)
        client, queue = h.client, h.queue
        run_id = uuid4()
        r = client.post(
            "/v1/trace",
            headers={"x-api-key": "good"},
            json={
                "run_id": str(run_id),
                "seq": 3,
                "event": {"type": "run_start", "ts": "2026-01-01T00:00:00Z", "payload": {}},
            },
        )
        assert r.status_code == 202
        assert r.json() == {"status": "accepted"}
        assert len(queue.items) == 1
        topic, project_id, payload = queue.items[0]
        assert topic == "trace_event"
        assert project_id == scope.project_id
        assert payload["project_id"] == str(scope.project_id)
        assert payload["principal_id"] == str(scope.principal_id)
        assert payload["agent_type_id"] == str(scope.agent_type_id)
        assert payload["run_id"] == str(run_id)
        assert payload["seq"] == 3
        assert payload["event"]["type"] == "run_start"

    def test_trace_batch_enqueues_one_item_per_event_and_caps_at_500(
        self, scope: ProjectScope
    ) -> None:
        h = _client(scope=scope)
        client, queue = h.client, h.queue
        events = [
            {
                "run_id": str(uuid4()),
                "seq": i,
                "event": {"type": "run_start", "ts": "2026-01-01T00:00:00Z"},
            }
            for i in range(3)
        ]
        r = client.post(
            "/v1/trace/batch", headers={"x-api-key": "good"}, json={"events": events}
        )
        assert r.status_code == 202
        assert len(queue.items) == 3

        oversized = [
            {
                "run_id": str(uuid4()),
                "seq": 0,
                "event": {"type": "run_start", "ts": "2026-01-01T00:00:00Z"},
            }
            for _ in range(501)
        ]
        r = client.post(
            "/v1/trace/batch", headers={"x-api-key": "good"}, json={"events": oversized}
        )
        assert r.status_code == 422

    def test_feedback_enqueues_outcome_event(self, scope: ProjectScope) -> None:
        h = _client(scope=scope)
        client, queue = h.client, h.queue
        r = client.post(
            "/v1/feedback",
            headers={"x-api-key": "good"},
            json={
                "run_id": str(uuid4()),
                "event": {
                    "adapter": "verdict",
                    "outcome": "positive",
                    "event_id": str(uuid4()),
                },
            },
        )
        assert r.status_code == 202
        topic, project_id, payload = queue.items[0]
        assert topic == "outcome_event"
        assert project_id == scope.project_id
        assert payload["event"]["adapter"] == "verdict"
        assert "weight" not in payload["event"]

    def test_propose_memory_enqueues_proposal(self, scope: ProjectScope) -> None:
        h = _client(scope=scope)
        client, queue = h.client, h.queue
        r = client.post(
            "/v1/propose_memory",
            headers={"x-api-key": "good"},
            json={
                "run_id": str(uuid4()),
                "proposal": {
                    "mem_type": "lesson",
                    "content": "always check X before Y",
                    "claimed_scope": "agent_type",
                },
            },
        )
        assert r.status_code == 202
        topic, project_id, payload = queue.items[0]
        assert topic == "memory_proposal"
        assert project_id == scope.project_id
        assert payload["proposal"]["mem_type"] == "lesson"

    def test_invalidation_persists_under_the_callers_own_project(
        self, scope: ProjectScope
    ) -> None:
        """C-31. As merged this route authenticated, resolved scope, returned
        202 "accepted" — and dropped the body on the floor. That is the one
        failure mode a 202 must never have: every future integration test
        would have passed by accident, because "accepted" and "accepted and
        stored" look identical from the wire. The assertion is therefore on
        the WRITE, not the status code.
        """
        harness = _client(scope=scope)
        assert harness.client.post("/v1/invalidation", json={"kind": "x"}).status_code == 401

        r = harness.client.post(
            "/v1/invalidation",
            headers={"x-api-key": "good"},
            json={"kind": "tool_changed", "payload": {"tool_id": "search"}},
        )
        assert r.status_code == 202
        assert harness.invalidations.rows == [
            (scope.project_id, "tool_changed", {"tool_id": "search"})
        ]
        # Not a queue write: §14 forbids a fourth topic, so this route is the
        # one /v1/* path that writes synchronously.
        assert harness.queue.items == []

    def test_invalidation_body_cannot_name_a_project(self, scope: ProjectScope) -> None:
        """`InvalidationIn` is `extra="forbid"` and declares no `project_id`
        (invariant 4). Belt-and-braces: `payload` is a free-form dict, so a
        `project_id` smuggled INSIDE it must land in the selector jsonb and
        never influence which partition the row goes to."""
        harness = _client(scope=scope)
        other = ProjectId(uuid4())

        assert (
            harness.client.post(
                "/v1/invalidation",
                headers={"x-api-key": "good"},
                json={"kind": "x", "project_id": str(other)},
            ).status_code
            == 422
        )
        assert harness.invalidations.rows == []

        assert (
            harness.client.post(
                "/v1/invalidation",
                headers={"x-api-key": "good"},
                json={"kind": "x", "payload": {"project_id": str(other)}},
            ).status_code
            == 202
        )
        assert harness.invalidations.rows[0][0] == scope.project_id


# --------------------------------------------------------------------------- #
# Leak-suite probe 2 offline: cross-project by-id == genuinely absent.
# --------------------------------------------------------------------------- #


def _memory_row(*, memory_id: UUID, project_id: ProjectId, content: str) -> MemoryItemRow:
    """A real `MemoryItemRow` — the route projects it through `MemoryItemOut`,
    so a fake dict would only prove the fake's own shape."""
    return MemoryItemRow(
        id=MemoryId(memory_id),
        project_id=project_id,
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="lesson",
        lane=Lane.QUALITY,
        trust_tier=TrustTier.A,
        status=Status.VALIDATED,
        content=content,
        content_hash=content_hash(content),
        token_count=7,
        subject_tag=None,
        q_value=0.5,
        confidence=0.5,
        scored_use_count=0,
        strike_count=0,
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(RunId(uuid4()),)),
        scan_verdict_id=uuid4(),
        schema_version=1,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        status_changed_at=None,
    )


class TestUniform404:
    """Leak-suite probe 2, offline. The reader really holds rows here: one in
    the caller's project (must be readable) and one in a FOREIGN project (must
    be indistinguishable from an id that was never minted)."""

    def test_own_project_memory_is_readable(self, scope: ProjectScope) -> None:
        harness = _client(scope=scope)
        memory_id = uuid4()
        harness.memory.put(
            scope.project_id,
            memory_id,
            _memory_row(memory_id=memory_id, project_id=scope.project_id, content="mine"),
        )

        r = harness.client.get(f"/admin/memory/{memory_id}", headers={"x-api-key": "good"})

        assert r.status_code == 200
        assert r.json()["content"] == "mine"
        assert r.json()["project_id"] == str(scope.project_id)

    def test_cross_project_and_absent_memory_are_byte_identical(self, scope: ProjectScope) -> None:
        harness = _client(scope=scope)
        foreign_project = ProjectId(uuid4())
        foreign_id = uuid4()
        harness.memory.put(
            foreign_project,
            foreign_id,
            _memory_row(
                memory_id=foreign_id, project_id=foreign_project, content="another tenant's secret"
            ),
        )
        absent_id = uuid4()

        r_foreign = harness.client.get(f"/admin/memory/{foreign_id}", headers={"x-api-key": "good"})
        r_absent = harness.client.get(f"/admin/memory/{absent_id}", headers={"x-api-key": "good"})

        assert r_absent.status_code == r_foreign.status_code == 404
        assert r_absent.json() == r_foreign.json() == {"detail": "not found"}
        # Byte-identical, not merely equal-after-parsing: a difference in key
        # order or whitespace is still a distinguisher.
        assert r_absent.content == r_foreign.content
        assert b"secret" not in r_foreign.content

    def test_route_never_reads_a_project_from_the_request(self, scope: ProjectScope) -> None:
        """A query string is the remaining smuggling surface once the body is
        gone (this route has no body at all) — it must not reach the reader."""
        harness = _client(scope=scope)
        foreign_project = ProjectId(uuid4())
        foreign_id = uuid4()
        harness.memory.put(
            foreign_project,
            foreign_id,
            _memory_row(memory_id=foreign_id, project_id=foreign_project, content="theirs"),
        )

        r = harness.client.get(
            f"/admin/memory/{foreign_id}",
            params={"project_id": str(foreign_project)},
            headers={"x-api-key": "good"},
        )
        assert r.status_code == 404


class TestExport:
    def test_streams_ndjson_scoped_to_caller(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        r = client.get("/export/project", headers={"x-api-key": "good"})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/x-ndjson")
        lines = [json.loads(line) for line in r.text.splitlines() if line]
        # FakeExporter yields nothing for any project but the scoped one, so a
        # route that stopped passing scope.project_id yields zero lines.
        assert lines == [
            {"table": "memory_item", "row": {"project_id": str(scope.project_id)}}
        ]

    def test_requires_authentication(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        assert client.get("/export/project").status_code == 401


class TestNoUnauthenticatedRoutes:
    """§14 api-auth DO-NOT list: `/healthz` is the ONLY unauthenticated route,
    and an unauthenticated caller must never be able to tell a well-formed
    body from a malformed one (that would be a free schema oracle)."""

    def test_healthz_is_the_only_open_route(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        assert client.get("/healthz").json() == {"status": "ok"}

        unauthenticated = [
            client.post("/v1/retrieve", json={"agent_type": "a", "run_ctx": _RUN_CTX}),
            client.post("/v1/trace", json={}),
            client.post("/v1/trace/batch", json={"events": []}),
            client.post("/v1/feedback", json={}),
            client.post("/v1/propose_memory", json={}),
            client.post("/v1/invalidation", json={"kind": "x"}),
            client.get(f"/admin/memory/{uuid4()}"),
            client.get("/export/project"),
            client.post("/admin/projects", json={"name": "p"}),
            client.post(
                "/admin/agents/register",
                json={
                    "project_id": str(uuid4()),
                    "agent_type": "a",
                    "principal": {"kind": "api_key"},
                },
            ),
        ]
        assert [r.status_code for r in unauthenticated] == [401] * len(unauthenticated)

    def test_credential_check_precedes_body_validation(self, scope: ProjectScope) -> None:
        """Garbage bodies on every authenticated route still get 401, never
        422 — otherwise an anonymous caller could map the wire schema by
        diffing validation errors."""
        client = _client(scope=scope).client
        for path in (
            "/v1/retrieve",
            "/v1/trace",
            "/v1/trace/batch",
            "/v1/feedback",
            "/v1/propose_memory",
            "/v1/invalidation",
        ):
            r = client.post(path, json={"totally": "wrong", "shape": 1})
            assert r.status_code == 401, path
            assert r.json() == {"detail": "authentication failed"}


class TestWireBounds:
    """Caller-controlled sizes are bounded at the wire (invariant 4's sibling
    concern: an authenticated caller must not be able to drive unbounded
    server-side allocation)."""

    def test_oversized_query_text_is_422(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        r = client.post(
            "/v1/retrieve",
            headers={"x-api-key": "good"},
            json={"agent_type": "a", "run_ctx": {"query_text": "x" * (MAX_QUERY_TEXT_CHARS + 1)}},
        )
        assert r.status_code == 422

    def test_negative_and_oversized_seq_are_422(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        event = {"type": "run_start", "ts": "2026-01-01T00:00:00Z"}
        for seq in (-1, MAX_SEQ + 1):
            r = client.post(
                "/v1/trace",
                headers={"x-api-key": "good"},
                json={"run_id": str(uuid4()), "seq": seq, "event": event},
            )
            assert r.status_code == 422, seq
