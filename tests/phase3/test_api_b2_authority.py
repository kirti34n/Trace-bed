"""B2 HTTP authority routing: roles, sealed business writes, and run fences."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tracebed.adapters.identity import Principal
from tracebed.api.deps import AppDeps
from tracebed.api.main import create_app
from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EmbeddingConfig, StorageConfig, TracebedSettings
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.enums import Arm, FeedbackSource, OutcomeCode, ProjectRole
from tracebed.domain.errors import AuthenticationFailed, NotFound
from tracebed.domain.events import RetrieveResult, RunContext, empty_context_block
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.budget import Deadline

pytestmark = pytest.mark.phase3

PROJECT = ProjectId(UUID("11111111-1111-1111-1111-111111111111"))
AGENT = AgentTypeId(UUID("22222222-2222-2222-2222-222222222222"))
PRINCIPAL = PrincipalId(UUID("33333333-3333-3333-3333-333333333333"))
AUTH = {"x-api-key": "b2-test"}


class _Verifier:
    def authenticate(
        self,
        *,
        authorization: str | None,
        api_key: str | None,
        deadline: RemainingBudget | None = None,
    ) -> Principal:
        del authorization, deadline
        if api_key != "b2-test":
            raise AuthenticationFailed("bad credential")
        return Principal(principal_id=PRINCIPAL, kind="api_key", external_ref="b2")


@dataclass
class _Resolver:
    access: AccessContext

    def resolve_access(
        self, principal_id: PrincipalId, *, deadline: RemainingBudget | None = None
    ) -> AccessContext:
        del deadline
        assert principal_id == PRINCIPAL
        return self.access


@dataclass
class _Queue:
    calls: list[tuple[AccessContext, tuple[object, ...]]] = field(default_factory=list)

    def enqueue_many_authorized(
        self, access: AccessContext, writes: tuple[object, ...]
    ) -> tuple[int, ...]:
        self.calls.append((access, writes))
        return tuple(range(len(writes)))


@dataclass
class _Opener:
    calls: list[tuple[AccessContext, RunId]] = field(default_factory=list)
    deadlines: list[RemainingBudget | None] = field(default_factory=list)

    def open(self, access: AccessContext, run_id: RunId) -> object:
        self.calls.append((access, run_id))
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
        del subject_tags
        self.calls.append((access, run_id))
        self.deadlines.append(deadline)
        yield type("Scope", (), {"audit": _Audit()})()


class _Audit:
    def record_terminal(self, **kwargs: object) -> None:
        del kwargs


@dataclass
class _Invalidations:
    calls: list[tuple[AccessContext, str, Mapping[str, object] | None]] = field(
        default_factory=list
    )

    def insert(
        self,
        access: AccessContext,
        event_type: str,
        selector: Mapping[str, object] | None = None,
    ) -> UUID:
        self.calls.append((access, event_type, selector))
        return uuid4()


@dataclass
class _Pipeline:
    calls: list[RunId] = field(default_factory=list)
    deadlines: list[Deadline | None] = field(default_factory=list)

    def retrieve(
        self,
        scope: ProjectScope,
        run_ctx: RunContext,
        *,
        session_id: str | None = None,
        run_id: RunId | None = None,
        deadline: Deadline | None = None,
        audit: object | None = None,
    ) -> RetrieveResult:
        del scope, run_ctx, session_id, audit
        assert type(run_id) is RunId
        self.calls.append(run_id)
        self.deadlines.append(deadline)
        return RetrieveResult(
            run_id=run_id.value,
            arm=Arm.MEMORY_ON,
            outcome_code=OutcomeCode.EMPTY_RESULT,
            context_block=empty_context_block(),
        )


class _Stubs:
    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        del principal_id
        raise AssertionError("B2 routes must not resolve legacy scope")

    def record_retrieval(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("pipeline route owns telemetry")

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> Any:
        del project_id, memory_id
        raise NotFound("not found")

    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]:
        del project_id
        return iter(())


@dataclass
class _Harness:
    client: TestClient
    queue: _Queue
    opener: _Opener
    invalidations: _Invalidations
    pipeline: _Pipeline


def _access(*roles: ProjectRole) -> AccessContext:
    grants: list[GrantBinding] = []
    for role in roles:
        grants.append(
            GrantBinding(
                uuid4(),
                role,
                FeedbackSource.VERDICT if role is ProjectRole.FEEDBACK else None,
            )
        )
    return AccessContext(PROJECT, AGENT, PRINCIPAL, tuple(grants))


def _harness(*roles: ProjectRole) -> _Harness:
    queue = _Queue()
    opener = _Opener()
    invalidations = _Invalidations()
    pipeline = _Pipeline()
    stubs = _Stubs()
    deps = AppDeps(
        verifier=_Verifier(),
        resolver=stubs,
        queue=queue,
        telemetry=stubs,
        memory_reader=stubs,
        exporter=stubs,
        invalidations=invalidations,
        retrieval_opener=opener,
        access_resolver=_Resolver(_access(*roles)),
        clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        pipeline=pipeline,
    )
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
        embedding=EmbeddingConfig(model_version="test"),
    )
    return _Harness(TestClient(create_app(settings, deps)), queue, opener, invalidations, pipeline)


def _trace_body() -> dict[str, object]:
    return {
        "run_id": str(uuid4()),
        "seq": 0,
        "event": {"type": "run_start", "ts": "2026-01-01T00:00:00Z"},
    }


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/retrieve", {"agent_type": "ignored", "run_ctx": {"query_text": "q"}}),
        ("/v1/trace", _trace_body()),
        ("/v1/trace/batch", {"events": [_trace_body(), _trace_body()]}),
        (
            "/v1/propose_memory",
            {
                "run_id": str(uuid4()),
                "proposal": {"mem_type": "lesson", "content": "c", "claimed_scope": "agent_type"},
            },
        ),
        ("/v1/invalidation", {"kind": "changed"}),
    ],
)
def test_data_role_is_required_for_data_routes(path: str, body: dict[str, object]) -> None:
    assert (
        _harness(ProjectRole.FEEDBACK).client.post(path, json=body, headers=AUTH).status_code == 403
    )
    assert _harness(ProjectRole.DATA).client.post(path, json=body, headers=AUTH).status_code in {
        200,
        202,
    }


def test_feedback_is_source_checked_and_seals_adapter_from_the_queue_payload() -> None:
    h = _harness(ProjectRole.FEEDBACK)
    body = {
        "run_id": str(uuid4()),
        "event": {"adapter": "verdict", "outcome": "positive", "event_id": str(uuid4())},
    }
    assert h.client.post("/v1/feedback", json=body, headers=AUTH).status_code == 202
    write = h.queue.calls[0][1][0]
    assert write.to_json_payload().keys() == {"event_id", "outcome", "payload", "occurred_at"}
    body["event"]["adapter"] = "downstream"  # type: ignore[index]
    assert h.client.post("/v1/feedback", json=body, headers=AUTH).status_code == 403


def test_trace_batch_calls_the_authorized_producer_once() -> None:
    h = _harness(ProjectRole.DATA)
    assert (
        h.client.post(
            "/v1/trace/batch", json={"events": [_trace_body(), _trace_body()]}, headers=AUTH
        ).status_code
        == 202
    )
    assert len(h.queue.calls) == 1
    assert len(h.queue.calls[0][1]) == 2


def test_retrieval_opens_then_passes_the_same_prebound_run_to_pipeline() -> None:
    h = _harness(ProjectRole.DATA)
    client = TestClient(h.client.app, raise_server_exceptions=False)
    response = client.post(
        "/v1/retrieve", json={"agent_type": "ignored", "run_ctx": {"query_text": "q"}}, headers=AUTH
    )
    assert response.status_code == 200
    assert len(h.opener.calls) == len(h.pipeline.calls) == 1
    assert h.opener.calls[0][1] == h.pipeline.calls[0]
    assert isinstance(h.pipeline.deadlines[0], Deadline)
    assert h.opener.deadlines == h.pipeline.deadlines
    assert response.json()["run_id"] == str(h.pipeline.calls[0].value)


def test_result_is_not_published_when_hold_exit_fails() -> None:
    """The worker may compute a result, but it cannot escape a failed fence exit."""

    @dataclass
    class _FailingHold:
        @contextmanager
        def hold(
            self,
            access: AccessContext,
            run_id: RunId,
            *,
            subject_tags: tuple[str, ...] = (),
            deadline: RemainingBudget | None = None,
        ) -> Iterator[object]:
            del access, run_id, subject_tags, deadline
            yield type("Scope", (), {"audit": _Audit()})()
            raise RuntimeError("commit failed")

    h = _harness(ProjectRole.DATA)
    h.client.app.state.deps.retrieval_opener = _FailingHold()
    client = TestClient(h.client.app, raise_server_exceptions=False)
    response = client.post(
        "/v1/retrieve", json={"agent_type": "ignored", "run_ctx": {"query_text": "q"}}, headers=AUTH
    )
    assert response.status_code == 500
    assert h.pipeline.calls, "the result was computed inside the held transaction"
    assert "run_id" not in response.text


def test_admin_export_and_whoami_have_distinct_role_gates() -> None:
    feedback = _harness(ProjectRole.FEEDBACK)
    assert feedback.client.get("/admin/whoami", headers=AUTH).status_code == 200
    assert feedback.client.get("/admin/memory", headers=AUTH).status_code == 403
    assert feedback.client.get("/export/project", headers=AUTH).status_code == 403
    assert _harness(ProjectRole.ADMIN).client.get("/admin/memory", headers=AUTH).status_code == 500
    assert (
        _harness(ProjectRole.EXPORT).client.get("/export/project", headers=AUTH).status_code == 200
    )


def test_invalidation_receives_the_authoritative_context() -> None:
    h = _harness(ProjectRole.DATA)
    assert (
        h.client.post("/v1/invalidation", json={"kind": "changed"}, headers=AUTH).status_code == 202
    )
    assert len(h.invalidations.calls) == 1
    access, event_type, selector = h.invalidations.calls[0]
    assert access.project_id == PROJECT
    assert event_type == "changed"
    assert selector == {}


def test_normal_api_has_no_owner_dsn_or_owner_provisioning_surface() -> None:
    """The owner-only onboarding CLI is never injected into the HTTP service."""

    compose = Path("docker/compose.yaml").read_text(encoding="utf-8")
    api_section = compose.split("\n  api:\n", maxsplit=1)[1].split("\n  worker:\n", maxsplit=1)[0]
    assert "TB_STORAGE__ADMIN_PG_DSN" not in api_section
    assert "tracebed_owner" not in api_section
    assert "TB_STORAGE__PG_DSN" not in compose.split("\nservices:\n", maxsplit=1)[0]

    annotations = AppDeps.__annotations__
    assert "access_resolver" in annotations
    assert all("owner" not in name and "provision" not in name for name in annotations)
