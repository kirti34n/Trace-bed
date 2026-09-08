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
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tracebed.adapters.identity import Principal
from tracebed.api.deps import AppDeps, authenticate_data_access
from tracebed.api.main import create_app
from tracebed.api.models import MAX_QUERY_TEXT_CHARS, MAX_SEQ
from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.canonical import content_hash
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EmbeddingConfig, StorageConfig, TracebedSettings
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.enums import (
    Arm,
    FeedbackSource,
    Lane,
    MemType,
    OutcomeCode,
    ProjectRole,
    ProvenanceClass,
    ScopeType,
    TrustTier,
)
from tracebed.domain.errors import (
    AuthenticationFailed,
    AuthorizationDenied,
    NotFound,
    RequestDeadlineExceeded,
)
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
from tracebed.hotpath.budget import Deadline
from tracebed.stores.pg.rows import MemoryItemRow

pytestmark = pytest.mark.phase0


# --------------------------------------------------------------------------- #
# Fakes — chunk-local (contract §13.1: harness's shared fixtures cover
# fixture *names*, not chunk-specific fake implementations).
# --------------------------------------------------------------------------- #


@dataclass
class FakeQueue:
    calls: list[tuple[AccessContext, tuple[object, ...]]] = field(default_factory=list)

    def enqueue_many_authorized(
        self,
        access: AccessContext,
        writes: tuple[object, ...],
    ) -> tuple[int, ...]:
        self.calls.append((access, writes))
        return tuple(range(1, len(writes) + 1))


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
    def create_agent_registration(
        self,
        project_id: ProjectId,
        agent_type_name: str,
        principal_kind: str,
        external_ref: str,
        key_hash: str | None,
    ) -> tuple[PrincipalId, AgentTypeId]:
        del project_id, agent_type_name, principal_kind, external_ref, key_hash
        return PrincipalId(uuid4()), AgentTypeId(uuid4())


class FakeProjectProvisioner:
    def provision_project(self, **kwargs: object) -> ProjectId:
        del kwargs
        raise AssertionError("project provisioning is not exercised by scoped routes")


@dataclass
class FakeVerifier:
    """`api_key == "good"` authenticates as one fixed principal; anything
    else fails — enough surface for the scope-derivation tests, which are
    not re-proving `ApiKeyVerifier` itself (that is `test_auth.py`'s job)."""

    principal_id: PrincipalId

    def authenticate(
        self,
        *,
        authorization: str | None,
        api_key: str | None,
        deadline: RemainingBudget | None = None,
    ) -> Principal:
        del authorization, deadline
        if api_key == "good":
            return Principal(principal_id=self.principal_id, kind="api_key", external_ref="k1")
        raise AuthenticationFailed("bad credential")


@dataclass
class FakeResolver:
    scope: ProjectScope

    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        del principal_id
        return self.scope


@dataclass
class FakeAccessResolver:
    scope: ProjectScope

    def resolve_access(
        self, principal_id: PrincipalId, *, deadline: RemainingBudget | None = None
    ) -> AccessContext:
        del deadline
        assert principal_id == self.scope.principal_id
        return AccessContext(
            project_id=self.scope.project_id,
            agent_type_id=self.scope.agent_type_id,
            principal_id=self.scope.principal_id,
            grants=(
                GrantBinding(uuid4(), ProjectRole.DATA),
                GrantBinding(uuid4(), ProjectRole.FEEDBACK, FeedbackSource.VERDICT),
                GrantBinding(uuid4(), ProjectRole.ADMIN),
                GrantBinding(uuid4(), ProjectRole.EXPORT),
            ),
        )


class FakeRetrievalOpener:
    def __init__(self, telemetry: FakeTelemetry, project_id: ProjectId) -> None:
        self._telemetry = telemetry
        self._project_id = project_id

    def open(self, access: AccessContext, run_id: RunId) -> object:
        assert access.grant_for(ProjectRole.DATA) is not None
        assert type(run_id) is RunId
        return object()

    @contextmanager
    def hold(
        self,
        access: AccessContext,
        run_id: RunId,
        *,
        subject_tags: tuple[str, ...] = (),
        deadline: RemainingBudget | None = None,
    ) -> Iterator[object]:
        del subject_tags, deadline
        assert access.grant_for(ProjectRole.DATA) is not None
        assert type(run_id) is RunId
        yield type("Scope", (), {"audit": _Audit(self._telemetry, self._project_id)})()


class _Audit:
    def __init__(self, telemetry: FakeTelemetry, project_id: ProjectId) -> None:
        self._telemetry, self._project_id = telemetry, project_id

    def record_terminal(self, **kwargs: object) -> None:
        row = kwargs["row"]
        self._telemetry.record_retrieval(
            self._project_id,
            row.run_id,
            outcome_code=row.outcome_code,
            latency_ms=row.latency_ms,
            embed_latency_ms=row.embed_latency_ms,
            candidates_considered=row.candidates_considered,
            top_score=row.top_score,
            arm=row.arm,
        )


class ExpiredPipeline:
    def retrieve(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RequestDeadlineExceeded()


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

    def insert(
        self,
        access: AccessContext,
        event_type: str,
        selector: Mapping[str, Any] | None = None,
    ) -> UUID:
        self.rows.append((access.project_id, event_type, selector))
        return uuid4()


@dataclass
class Harness:
    client: TestClient
    queue: FakeQueue
    telemetry: FakeTelemetry
    memory: FakeMemoryReader
    invalidations: FakeInvalidations


def _client(
    *,
    scope: ProjectScope,
    queue: FakeQueue | None = None,
    telemetry: FakeTelemetry | None = None,
    pipeline: object | None = None,
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
        retrieval_opener=FakeRetrievalOpener(telemetry, scope.project_id),
        access_resolver=FakeAccessResolver(scope),
        clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        pipeline=pipeline,  # type: ignore[arg-type]
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
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
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

    def test_late_successful_auth_does_not_begin_grant_resolution(
        self, scope: ProjectScope
    ) -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        deadline = Deadline(clock=clock, total_budget_ms=10, embed_timeout_ms=10)

        class LateVerifier:
            def authenticate(
                self,
                *,
                authorization: str | None,
                api_key: str | None,
                deadline: RemainingBudget | None = None,
            ) -> Principal:
                del authorization, api_key
                assert deadline is not None
                clock.advance(ms=10)
                return Principal(scope.principal_id, "api_key", "key")

        class NoGrantResolver:
            def resolve_access(self, principal_id: PrincipalId) -> AccessContext:
                del principal_id
                raise AssertionError("expired auth must not begin grant resolution")

        deps = SimpleNamespace(verifier=LateVerifier(), access_resolver=NoGrantResolver())
        with pytest.raises(RequestDeadlineExceeded):
            authenticate_data_access(
                cast(AppDeps, deps), authorization=None, api_key="good", deadline=deadline
            )

    def test_preexpired_budget_does_not_invoke_the_verifier(self, scope: ProjectScope) -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        deadline = Deadline(clock=clock, total_budget_ms=10, embed_timeout_ms=10)
        clock.advance(ms=10)

        class NeverVerifier:
            calls = 0

            def authenticate(
                self,
                *,
                authorization: str | None,
                api_key: str | None,
                deadline: RemainingBudget | None = None,
            ) -> Principal:
                del authorization, api_key, deadline
                self.calls += 1
                raise AssertionError("preexpired request must not authenticate")

        verifier = NeverVerifier()
        deps = SimpleNamespace(verifier=verifier, access_resolver=object())
        with pytest.raises(RequestDeadlineExceeded):
            authenticate_data_access(
                cast(AppDeps, deps), authorization=None, api_key="good", deadline=deadline
            )
        assert verifier.calls == 0

    def test_grant_resolver_receives_the_exact_request_budget(self, scope: ProjectScope) -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        deadline = Deadline(clock=clock, total_budget_ms=100, embed_timeout_ms=100)

        class Verifier:
            def authenticate(
                self,
                *,
                authorization: str | None,
                api_key: str | None,
                deadline: RemainingBudget | None = None,
            ) -> Principal:
                del authorization, api_key
                assert deadline is not None
                return Principal(scope.principal_id, "api_key", "key")

        class Resolver:
            seen: RemainingBudget | None = None

            def resolve_access(
                self, principal_id: PrincipalId, *, deadline: RemainingBudget | None = None
            ) -> AccessContext:
                assert principal_id == scope.principal_id
                self.seen = deadline
                return AccessContext(
                    project_id=scope.project_id,
                    agent_type_id=scope.agent_type_id,
                    principal_id=scope.principal_id,
                    grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
                )

        resolver = Resolver()
        deps = SimpleNamespace(verifier=Verifier(), access_resolver=resolver)

        access = authenticate_data_access(
            cast(AppDeps, deps), authorization=None, api_key="good", deadline=deadline
        )

        assert access.principal_id == scope.principal_id
        assert resolver.seen is deadline

    @pytest.mark.parametrize(
        ("grant", "expected"), [(False, AuthorizationDenied), (True, RequestDeadlineExceeded)]
    )
    def test_evaluated_denial_wins_but_late_valid_grant_is_503(
        self, scope: ProjectScope, grant: bool, expected: type[Exception]
    ) -> None:
        clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
        deadline = Deadline(clock=clock, total_budget_ms=10, embed_timeout_ms=10)

        class Verifier:
            def authenticate(
                self,
                *,
                authorization: str | None,
                api_key: str | None,
                deadline: RemainingBudget | None = None,
            ) -> Principal:
                del authorization, api_key
                assert deadline is not None
                return Principal(scope.principal_id, "api_key", "key")

        class Resolver:
            def resolve_access(
                self, principal_id: PrincipalId, *, deadline: RemainingBudget | None = None
            ) -> AccessContext:
                del principal_id
                assert deadline is not None
                clock.advance(ms=10)
                return AccessContext(
                    project_id=scope.project_id,
                    agent_type_id=scope.agent_type_id,
                    principal_id=scope.principal_id,
                    grants=(GrantBinding(uuid4(), ProjectRole.DATA),)
                    if grant
                    else (GrantBinding(uuid4(), ProjectRole.FEEDBACK, FeedbackSource.VERDICT),),
                )

        deps = SimpleNamespace(verifier=Verifier(), access_resolver=Resolver())
        with pytest.raises(expected):
            authenticate_data_access(
                cast(AppDeps, deps), authorization=None, api_key="good", deadline=deadline
            )

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

    def test_retrieve_validation_is_json_safe_and_body_located(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        malformed = client.post(
            "/v1/retrieve",
            headers={"x-api-key": "good", "content-type": "application/json"},
            content=b"{",
        )
        assert malformed.status_code == 422
        unsupported = client.post("/v1/retrieve", headers={"x-api-key": "good"}, json=[])
        assert unsupported.status_code == 422
        invalid_user = client.post(
            "/v1/retrieve",
            headers={"x-api-key": "good"},
            json={"agent_type": "a", "run_ctx": {**_RUN_CTX, "user_ref": " "}},
        )
        assert invalid_user.status_code == 422
        error = invalid_user.json()["detail"][0]
        assert error["loc"][:3] == ["body", "run_ctx", "user_ref"]

    def test_retrieve_openapi_retains_the_public_request_schema(self, scope: ProjectScope) -> None:
        schema = _client(scope=scope).client.get("/openapi.json").json()
        request_schema = schema["paths"]["/v1/retrieve"]["post"]["requestBody"]["content"][
            "application/json"
        ]["schema"]
        assert request_schema == {"$ref": "#/components/schemas/RetrieveIn"}
        components = schema["components"]["schemas"]

        seen_refs: set[str] = set()

        def assert_local_refs_resolve(node: object) -> None:
            if isinstance(node, dict):
                ref = node.get("$ref")
                if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
                    name = ref.rsplit("/", maxsplit=1)[1]
                    assert name in components
                    if name not in seen_refs:
                        seen_refs.add(name)
                        assert_local_refs_resolve(components[name])
                for value in node.values():
                    assert_local_refs_resolve(value)
            elif isinstance(node, list):
                for value in node:
                    assert_local_refs_resolve(value)

        assert_local_refs_resolve(components["RetrieveIn"])
        retrieve = components["RetrieveIn"]
        assert set(retrieve["properties"]) >= {"agent_type", "run_ctx"}
        assert_local_refs_resolve(request_schema)


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

    def test_request_deadline_abort_is_opaque_503_without_result_or_telemetry(
        self, scope: ProjectScope
    ) -> None:
        h = _client(scope=scope, pipeline=ExpiredPipeline())
        r = h.client.post(
            "/v1/retrieve",
            headers={"x-api-key": "good"},
            json={"agent_type": "a", "run_ctx": _RUN_CTX},
        )

        assert r.status_code == 503
        assert r.json() == {"detail": "unavailable"}
        assert "run_id" not in r.json()
        assert "context_block" not in r.json()
        assert h.telemetry.calls == []

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
        assert len(queue.calls) == 1
        access, writes = queue.calls[0]
        assert access.project_id == scope.project_id
        assert len(writes) == 1
        write = writes[0]
        assert write.topic == "trace_event"
        assert write.run_id.value == run_id
        assert write.to_json_payload() == {
            "seq": 3,
            "event": {"type": "run_start", "ts": "2026-01-01T00:00:00Z", "payload": {}},
        }

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
        r = client.post("/v1/trace/batch", headers={"x-api-key": "good"}, json={"events": events})
        assert r.status_code == 202
        assert len(queue.calls) == 1
        assert len(queue.calls[0][1]) == 3

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
        access, writes = queue.calls[0]
        assert access.project_id == scope.project_id
        assert writes[0].topic == "outcome_event"
        assert writes[0].to_json_payload()["outcome"] == "positive"
        assert "adapter" not in writes[0].to_json_payload()

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
        access, writes = queue.calls[0]
        assert access.project_id == scope.project_id
        assert writes[0].topic == "memory_proposal"
        assert writes[0].to_json_payload()["proposal"]["mem_type"] == "lesson"

    def test_invalidation_persists_under_the_callers_own_project(self, scope: ProjectScope) -> None:
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
        assert harness.queue.calls == []

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
        assert lines == [{"table": "memory_item", "row": {"project_id": str(scope.project_id)}}]

    def test_requires_authentication(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        assert client.get("/export/project").status_code == 401


class TestNoUnauthenticatedRoutes:
    """§14 api-auth DO-NOT list: liveness/readiness are unauthenticated,
    and an unauthenticated caller must never be able to tell a well-formed
    body from a malformed one (that would be a free schema oracle)."""

    def test_healthz_is_the_only_open_route(self, scope: ProjectScope) -> None:
        client = _client(scope=scope).client
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").status_code == 503

        unauthenticated = [
            client.post("/v1/retrieve", json={"agent_type": "a", "run_ctx": _RUN_CTX}),
            client.post("/v1/trace", json={}),
            client.post("/v1/trace/batch", json={"events": []}),
            client.post("/v1/feedback", json={}),
            client.post("/v1/propose_memory", json={}),
            client.post("/v1/invalidation", json={"kind": "x"}),
            client.get(f"/admin/memory/{uuid4()}"),
            client.get("/export/project"),
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
