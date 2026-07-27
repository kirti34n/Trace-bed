"""`/admin/*` routes (PHASE0-CONTRACT.md §9.3, §14 api-auth DO-NOT list).

Fully offline via `TestClient` + fake `AppDeps` (contract §12). Proves: both
registry-creating routes reject a missing/wrong `X-Admin-Key` and accept the
right one; `POST /admin/projects` composes registry + partitions + KEK
provisioning in order; `POST /admin/agents/register` mints a one-time
plaintext `tb_sk_<key_id>.<secret>` for an `api_key` principal and none at
all for an `oidc_sub` one; a duplicate registration surfaces as 409; a
malformed `principal` sub-object (missing `sub` for `oidc_sub`) is 422
before any registry write happens.
"""

from __future__ import annotations

import hashlib
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
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import AuthConfig, EmbeddingConfig, StorageConfig, TracebedSettings
from tracebed.domain.errors import AuthenticationFailed, DuplicateRegistration, NotFound
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId

pytestmark = pytest.mark.phase0

_ADMIN_KEY_ENV = "TB_TEST_ADMIN_KEY"
_ADMIN_KEY = "s3cret-admin-bootstrap-key"


class _NeverCalledVerifier:
    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        del authorization, api_key
        raise AuthenticationFailed("no principal auth configured in this test")


class _AlwaysAuthenticatesVerifier:
    """Stands in for a legitimate tenant whose own credential is valid — the
    question the test using it asks is whether valid *principal* auth is ever
    accepted where *admin-key* auth is required."""

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        del authorization, api_key
        return Principal(
            principal_id=PrincipalId(uuid4()), kind="api_key", external_ref="tenant"
        )


class _NeverCalledResolver:
    def resolve_project(self, principal_id: PrincipalId) -> Any:
        del principal_id
        raise AssertionError("resolve_project should not be reached by admin-key routes")


class FakeExporter:
    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]:
        del project_id
        return iter(())


class FakeMemoryReader:
    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> Any:
        del project_id, memory_id
        raise NotFound("not found")


@dataclass
class FakeAdmin:
    """Records every call so tests can assert argument values without a database.

    `create_agent_registration` is the ONE registry write the route makes
    (C-30): the three underlying inserts share a transaction inside `Repo`, so
    a fake that still exposed `create_agent_type`/`create_principal`/
    `register_agent` separately would let a route that re-composed them go
    unnoticed. It raises `DuplicateRegistration` when the same
    `(kind, external_ref)` registers twice, mirroring `principal`'s UNIQUE
    constraint — and records NOTHING when it raises, which is what lets
    `test_a_failed_registration_leaves_no_orphan_rows` assert atomicity.
    """

    created_projects: list[tuple[str, Mapping[str, object] | None]] = field(default_factory=list)
    created_agent_types: list[tuple[ProjectId, str]] = field(default_factory=list)
    created_principals: list[tuple[str, str, str | None]] = field(default_factory=list)
    registrations: list[tuple[ProjectId, PrincipalId, AgentTypeId]] = field(default_factory=list)
    _taken_refs: set[tuple[str, str]] = field(default_factory=set)

    def create_project(
        self, name: str, retention_policy: Mapping[str, object] | None = None
    ) -> ProjectId:
        self.created_projects.append((name, retention_policy))
        return ProjectId(uuid4())

    def create_agent_registration(
        self,
        project_id: ProjectId,
        agent_type_name: str,
        principal_kind: str,
        external_ref: str,
        key_hash: str | None,
    ) -> tuple[PrincipalId, AgentTypeId]:
        if (principal_kind, external_ref) in self._taken_refs:
            # Nothing appended: the real method's three inserts share one
            # transaction, so a rejected call leaves the registry untouched.
            raise DuplicateRegistration("principal already registered")
        self._taken_refs.add((principal_kind, external_ref))
        principal_id = PrincipalId(uuid4())
        agent_type_id = AgentTypeId(uuid4())
        self.created_agent_types.append((project_id, agent_type_name))
        self.created_principals.append((principal_kind, external_ref, key_hash))
        self.registrations.append((project_id, principal_id, agent_type_id))
        return principal_id, agent_type_id


@dataclass
class FakeInvalidations:
    """`AppDeps.invalidations` (C-31). Records `(project_id, event_type, selector)`
    so a test can prove the route wrote the caller's OWN project id and the
    body it was handed — a route that returns 202 while dropping the event is
    the failure this fake exists to make visible."""

    rows: list[tuple[ProjectId, str, Mapping[str, object] | None]] = field(default_factory=list)

    def insert_invalidation_event(
        self,
        project_id: ProjectId,
        event_type: str,
        selector: Mapping[str, object] | None = None,
    ) -> UUID:
        self.rows.append((project_id, event_type, selector))
        return uuid4()


@dataclass
class FakePartitions:
    calls: list[ProjectId] = field(default_factory=list)

    def create_project_partitions(self, project_id: ProjectId) -> None:
        self.calls.append(project_id)


@dataclass
class FakeKeys:
    calls: list[ProjectId] = field(default_factory=list)

    def ensure_project_kek(self, project_id: ProjectId) -> None:
        self.calls.append(project_id)


class FakeQueue:
    def enqueue(
        self,
        topic: str,
        project_id: ProjectId,
        payload: Mapping[str, object],
        priority: int = 100,
        available_at: datetime | None = None,
    ) -> int:
        raise AssertionError("no admin route enqueues")


class FakeTelemetry:
    def record_retrieval(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("no admin route records telemetry")


@dataclass
class Harness:
    client: TestClient
    admin: FakeAdmin
    partitions: FakePartitions
    keys: FakeKeys


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> Harness:
    monkeypatch.setenv(_ADMIN_KEY_ENV, _ADMIN_KEY)
    admin = FakeAdmin()
    partitions = FakePartitions()
    keys = FakeKeys()
    deps = AppDeps(
        verifier=_NeverCalledVerifier(),
        resolver=_NeverCalledResolver(),
        queue=FakeQueue(),
        telemetry=FakeTelemetry(),
        memory_reader=FakeMemoryReader(),
        exporter=FakeExporter(),
        invalidations=FakeInvalidations(),
        admin=admin,
        partitions=partitions,
        keys=keys,
        clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
    )
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
        embedding=EmbeddingConfig(model_version="test"),
        auth=AuthConfig(admin_key_env=_ADMIN_KEY_ENV),
    )
    app = create_app(settings, deps)
    return Harness(client=TestClient(app), admin=admin, partitions=partitions, keys=keys)


# --------------------------------------------------------------------------- #
# C-20: wrong / missing / unconfigured admin key.
# --------------------------------------------------------------------------- #


class TestAdminKeyGate:
    def test_missing_admin_key_header_is_401(self, harness: Harness) -> None:
        r = harness.client.post("/admin/projects", json={"name": "p1"})
        assert r.status_code == 401
        assert r.json() == {"detail": "authentication failed"}
        assert harness.admin.created_projects == []

    def test_wrong_admin_key_is_401(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/projects", headers={"x-admin-key": "not-the-key"}, json={"name": "p1"}
        )
        assert r.status_code == 401
        assert harness.admin.created_projects == []

    def test_register_agent_also_gated(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/agents/register",
            json={
                "project_id": str(uuid4()),
                "agent_type": "worker",
                "principal": {"kind": "api_key"},
            },
        )
        assert r.status_code == 401
        assert harness.admin.created_agent_types == []

    def test_unconfigured_admin_key_env_rejects_everything(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No TB_TEST_ADMIN_KEY set at all -- app.state.admin_key_hash is None.
        monkeypatch.delenv(_ADMIN_KEY_ENV, raising=False)
        deps = AppDeps(
            verifier=_NeverCalledVerifier(),
            resolver=_NeverCalledResolver(),
            queue=FakeQueue(),
            telemetry=FakeTelemetry(),
            memory_reader=FakeMemoryReader(),
            exporter=FakeExporter(),
            invalidations=FakeInvalidations(),
            admin=FakeAdmin(),
            partitions=FakePartitions(),
            keys=FakeKeys(),
            clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        )
        settings = TracebedSettings(
            storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
            embedding=EmbeddingConfig(model_version="test"),
            auth=AuthConfig(admin_key_env=_ADMIN_KEY_ENV),
        )
        client = TestClient(create_app(settings, deps))
        r = client.post("/admin/projects", headers={"x-admin-key": "anything-at-all"}, json={"name": "p"})
        assert r.status_code == 401

    def test_correct_admin_key_passes(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/projects", headers={"x-admin-key": _ADMIN_KEY}, json={"name": "p1"}
        )
        assert r.status_code == 201

    def test_principal_credentials_cannot_substitute_for_the_admin_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The registry-write plane is a SEPARATE credential (C-20). An
        ordinary tenant whose API key authenticates perfectly on `/v1/*` must
        not be able to create projects or mint principals: that is tenant ->
        platform-admin privilege escalation, and it would let a tenant mint
        credentials into any project id it names.
        """
        monkeypatch.setenv(_ADMIN_KEY_ENV, _ADMIN_KEY)
        deps = AppDeps(
            verifier=_AlwaysAuthenticatesVerifier(),
            resolver=_NeverCalledResolver(),
            queue=FakeQueue(),
            telemetry=FakeTelemetry(),
            memory_reader=FakeMemoryReader(),
            exporter=FakeExporter(),
            invalidations=FakeInvalidations(),
            admin=FakeAdmin(),
            partitions=FakePartitions(),
            keys=FakeKeys(),
            clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        )
        settings = TracebedSettings(
            storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
            embedding=EmbeddingConfig(model_version="test"),
            auth=AuthConfig(admin_key_env=_ADMIN_KEY_ENV),
        )
        client = TestClient(create_app(settings, deps))

        for headers in (
            {"x-api-key": "a-perfectly-valid-tenant-key"},
            {"authorization": "Bearer a-perfectly-valid-tenant-token"},
        ):
            assert (
                client.post("/admin/projects", headers=headers, json={"name": "p"}).status_code
                == 401
            )
            assert (
                client.post(
                    "/admin/agents/register",
                    headers=headers,
                    json={
                        "project_id": str(uuid4()),
                        "agent_type": "a",
                        "principal": {"kind": "api_key"},
                    },
                ).status_code
                == 401
            )

    def test_unauthenticated_caller_cannot_probe_the_body_schema(self, harness: Harness) -> None:
        """A malformed body without the admin key must still be 401, never
        422 — a 422 would hand an anonymous caller the registry wire schema."""
        r = harness.client.post("/admin/projects", json={"not": "the right shape"})
        assert r.status_code == 401
        assert r.json() == {"detail": "authentication failed"}


# --------------------------------------------------------------------------- #
# POST /admin/projects.
# --------------------------------------------------------------------------- #


class TestCreateProject:
    def test_composes_registry_partitions_and_kek_in_order(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/projects",
            headers={"x-admin-key": _ADMIN_KEY},
            json={"name": "acme-prod", "retention_policy": {"days": 90}},
        )
        assert r.status_code == 201
        project_id = ProjectId(r.json()["project_id"])

        assert harness.admin.created_projects == [("acme-prod", {"days": 90})]
        assert harness.partitions.calls == [project_id]
        assert harness.keys.calls == [project_id]

    def test_project_id_field_forbidden_on_create(self, harness: Harness) -> None:
        # Creating a project is the one place project_id is NAMED at all
        # (the admin is choosing the id to provision partitions/KEK under —
        # contract §14) but it is chosen server-side, never client-supplied.
        r = harness.client.post(
            "/admin/projects",
            headers={"x-admin-key": _ADMIN_KEY},
            json={"name": "p", "project_id": str(uuid4())},
        )
        assert r.status_code == 422


# --------------------------------------------------------------------------- #
# POST /admin/agents/register.
# --------------------------------------------------------------------------- #


class TestRegisterAgent:
    def test_api_key_principal_returns_one_time_plaintext_key(self, harness: Harness) -> None:
        project_id = uuid4()
        r = harness.client.post(
            "/admin/agents/register",
            headers={"x-admin-key": _ADMIN_KEY},
            json={
                "project_id": str(project_id),
                "agent_type": "coder",
                "principal": {"kind": "api_key"},
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["api_key"] is not None
        assert body["api_key"].startswith("tb_sk_")
        key_id, _, secret = body["api_key"].removeprefix("tb_sk_").partition(".")
        assert key_id and secret

        kind, external_ref, key_hash = harness.admin.created_principals[0]
        assert kind == "api_key"
        assert external_ref == key_id
        assert key_hash == hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def test_oidc_sub_principal_returns_no_api_key(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/agents/register",
            headers={"x-admin-key": _ADMIN_KEY},
            json={
                "project_id": str(uuid4()),
                "agent_type": "human-reviewer",
                "principal": {"kind": "oidc_sub", "sub": "auth0|abc123"},
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["api_key"] is None
        kind, external_ref, key_hash = harness.admin.created_principals[0]
        assert (kind, external_ref, key_hash) == ("oidc_sub", "auth0|abc123", None)

    def test_oidc_sub_without_sub_is_422(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/agents/register",
            headers={"x-admin-key": _ADMIN_KEY},
            json={
                "project_id": str(uuid4()),
                "agent_type": "human-reviewer",
                "principal": {"kind": "oidc_sub"},
            },
        )
        assert r.status_code == 422
        assert harness.admin.created_principals == []

    def test_api_key_with_sub_is_422(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/agents/register",
            headers={"x-admin-key": _ADMIN_KEY},
            json={
                "project_id": str(uuid4()),
                "agent_type": "coder",
                "principal": {"kind": "api_key", "sub": "should-not-be-here"},
            },
        )
        assert r.status_code == 422

    def test_unknown_principal_kind_is_422(self, harness: Harness) -> None:
        r = harness.client.post(
            "/admin/agents/register",
            headers={"x-admin-key": _ADMIN_KEY},
            json={
                "project_id": str(uuid4()),
                "agent_type": "coder",
                "principal": {"kind": "host_asserted_actor", "sub": "trust-me"},
            },
        )
        assert r.status_code == 422
        assert harness.admin.created_principals == []

    def test_empty_names_are_422_and_write_nothing(self, harness: Harness) -> None:
        """Registry rows are what `resolve_project` later keys off; an empty
        or absurd name is a body-shape error, not a row."""
        assert (
            harness.client.post(
                "/admin/projects", headers={"x-admin-key": _ADMIN_KEY}, json={"name": ""}
            ).status_code
            == 422
        )
        assert (
            harness.client.post(
                "/admin/projects",
                headers={"x-admin-key": _ADMIN_KEY},
                json={"name": "n" * 100_000},
            ).status_code
            == 422
        )
        assert (
            harness.client.post(
                "/admin/agents/register",
                headers={"x-admin-key": _ADMIN_KEY},
                json={
                    "project_id": str(uuid4()),
                    "agent_type": "",
                    "principal": {"kind": "api_key"},
                },
            ).status_code
            == 422
        )
        assert harness.admin.created_projects == []
        assert harness.admin.created_agent_types == []

    def test_duplicate_registration_is_409(self, harness: Harness) -> None:
        body = {
            "project_id": str(uuid4()),
            "agent_type": "coder",
            "principal": {"kind": "oidc_sub", "sub": "same-sub-both-times"},
        }
        first = harness.client.post(
            "/admin/agents/register", headers={"x-admin-key": _ADMIN_KEY}, json=body
        )
        assert first.status_code == 201

        # The same OIDC `sub` a second time collides on `principal`'s
        # UNIQUE(kind, external_ref), exactly as two admins racing to register
        # one identity would.
        second = harness.client.post(
            "/admin/agents/register", headers={"x-admin-key": _ADMIN_KEY}, json=body
        )
        assert second.status_code == 409
        assert second.json() == {"detail": "principal already registered"}

    def test_a_failed_registration_leaves_no_orphan_rows(self, harness: Harness) -> None:
        """C-30. Before the atomic builder the route made three independent
        registry writes; a 409 on the third committed an orphan `agent_type`
        AND an orphan `api_key` principal whose `key_hash` was live but whose
        plaintext had been returned to nobody. Every failed retry of a
        retryable admin call deposited one more undead credential.
        """
        body = {
            "project_id": str(uuid4()),
            "agent_type": "coder",
            "principal": {"kind": "oidc_sub", "sub": "collides"},
        }
        assert (
            harness.client.post(
                "/admin/agents/register", headers={"x-admin-key": _ADMIN_KEY}, json=body
            ).status_code
            == 201
        )
        before_types = list(harness.admin.created_agent_types)
        before_principals = list(harness.admin.created_principals)

        assert (
            harness.client.post(
                "/admin/agents/register", headers={"x-admin-key": _ADMIN_KEY}, json=body
            ).status_code
            == 409
        )

        assert harness.admin.created_agent_types == before_types
        assert harness.admin.created_principals == before_principals
