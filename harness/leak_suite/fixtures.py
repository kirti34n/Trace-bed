"""Fixtures for the cross-project leak suite (PHASE-0 Task 17; PHASE0-CONTRACT.md §13.1/§17).

WHY THIS FILE DOES NOT USE `tests/phase0/conftest.py`'s `pg_pool` / `repo` /
`work_queue` / `two_projects` fixtures, even though PHASE0-CONTRACT.md §13.1
assigns fixtures with those exact names to this chunk: the leak suite lives
under `harness/`, outside `tests/`, so pytest's conftest layering does not reach
it at all — those fixtures are simply not in scope here. (When this file was
written they were also broken: `pg_pool` built a `ScopedPool` that does not
exist and `work_queue` passed `WorkQueue` two of its three arguments. That has
since been fixed at integration, C-27/D-045, but the scoping reason stands on
its own.) Every fixture below is therefore self-contained: its own DSN probe,
its own pool, its own migration-currency check, its own two-project
provisioning — built the same way a real deployment would, through the admin
HTTP routes and the typed repository, never by hand-crafting rows outside a
`LeakProject` builder.

Everything here skips cleanly (never errors) when Postgres/Valkey is absent —
`leak_pg_dsn`/`leak_valkey_url` are the two skip points every other fixture
in this module funnels through, so there is exactly one skip message per
service, matching the pattern `tests/conftest.py::pg` already established for
the rest of the suite.
"""

from __future__ import annotations

import base64
import os
import secrets
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import psycopg
import pytest
from fastapi.testclient import TestClient

from tracebed.adapters.identity import (
    ApiKeyVerifier,
    ChainVerifier,
    Principal,
    PrincipalKind,
    PrincipalRecord,
)
from tracebed.api.deps import AppDeps
from tracebed.api.main import create_app
from tracebed.core.scans import ScanContext, scan
from tracebed.crypto.shred import EnvMasterKeyProvider, PlainSection, SubjectKeyManager
from tracebed.domain.canonical import canonical_json, content_hash
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EmbeddingConfig, QueueConfig, StorageConfig, TracebedSettings
from tracebed.domain.enums import (
    AdapterClass,
    InstrumentationSource,
    Lane,
    MemType,
    ProvenanceClass,
    ScopeType,
    TraceOutcomeStatus,
    TrustTier,
)
from tracebed.domain.errors import AuthenticationFailed, NotFound, ScopeResolutionFailed
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId, mint_run_id
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits
from tracebed.domain.state_machine import apply as apply_transition
from tracebed.stores.pg.ddl import PARTITIONED_TABLES
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.queue import WorkQueue
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.rows import (
    MemoryItemRow,
    OutcomeEventInsert,
    TraceIndexUpsert,
)
from tracebed.stores.pg.telemetry import Telemetry
from tracebed.stores.tracestore.fs import FsTraceStore

__all__ = [
    "APP_ROLE_PASSWORD",
    "SEED_ROW_SQL",
    "LeakProject",
    "app_role_conninfo",
    "leak_admin_key_env",
    "leak_app",
    "leak_client",
    "leak_clock",
    "leak_keys_manager",
    "leak_master_key_env",
    "leak_pg_dsn",
    "leak_pool",
    "leak_queue",
    "leak_repo",
    "leak_settings",
    "leak_tracestore",
    "leak_valkey",
    "leak_valkey_url",
    "offline_two_projects",
    "seed_all_partitioned_tables",
    "two_leak_projects",
]

# `tracebed_app`'s credential belongs to deployment, not to this harness
# (docker/initdb/01-roles.sql for compose/CI) — overridable so the probe can
# run against a stack that rotated it, mirroring test_partitions.py's pattern.
APP_ROLE_PASSWORD: str = os.environ.get("TB_APP_ROLE_PASSWORD", "tracebed_app_dev")

_ADMIN_KEY_ENV = "TB_ADMIN_KEY"
_MASTER_KEY_ENV = "TB_MASTER_KEY"


# --------------------------------------------------------------------------- #
# The provisioned-project shape every probe reads.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LeakProject:
    """One fully-provisioned project, built the way a real deployment would.

    Offline variants (`offline_two_projects`) populate every field with
    fake-but-well-shaped values so probes do not need two code paths — only
    the fixture that builds a `LeakProject` differs between offline and
    integration, never the probes that consume one.
    """

    label: str
    scope: ProjectScope
    api_key: str
    """Plaintext `tb_sk_...` (integration) or a fake bearer string (offline) —
    whatever `leak_client`'s configured verifier accepts for this project."""
    memory_id: MemoryId
    run_id: RunId
    payload_ref: str
    outcome_event_id: uuid.UUID


# --------------------------------------------------------------------------- #
# Real adapters wiring `AppDeps` to the live stack — small, deliberate
# duplicates of `api/main.py`'s private `_RepoPrincipalLookup` /
# `_RepoTelemetryAdapter` / `_PoolPartitionsAdapter` (leading-underscore, not
# exported, not part of any chunk's public surface). PHASE0-CONTRACT.md §13.1
# accepts chunk-local duplication of this shape precisely so the harness never
# has to reach into another chunk's private wiring.
# --------------------------------------------------------------------------- #


class _RepoPrincipalLookup:
    def __init__(self, repo: Repo) -> None:
        self._repo = repo

    def get_principal_by_external_ref(
        self, kind: PrincipalKind, external_ref: str
    ) -> PrincipalRecord | None:
        row = self._repo.get_principal_by_external_ref(external_ref, kind=kind)
        if row is None or row.kind != kind:
            return None
        return PrincipalRecord(
            principal_id=row.principal_id,
            kind=kind,
            external_ref=row.external_ref,
            key_hash=row.key_hash,
            revoked=row.revoked_at is not None,
        )


class _PoolPartitionsAdapter:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    def create_project_partitions(self, project_id: ProjectId) -> None:
        with self._pool.connection() as conn:
            create_project_partitions(conn, project_id)


# --------------------------------------------------------------------------- #
# Fake adapters for the fully-offline half of the suite. Deliberately
# separate implementations from the "real" ones above — a fake that happened
# to share code with the real adapter could hide a real-adapter bug behind an
# offline pass, which is precisely what an isolation gate must not do.
# --------------------------------------------------------------------------- #


class _FakeVerifier:
    """Maps a bearer `X-API-Key`-shaped string straight to a `Principal` —
    no hashing, no lookup table indirection, because what is under test in
    the offline probes is routing/error-shape, not credential verification
    (that is `test_auth.py`'s job, owner api-auth)."""

    def __init__(self, principals: Mapping[str, Principal]) -> None:
        self._principals = principals

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
        del authorization
        if api_key and api_key in self._principals:
            return self._principals[api_key]
        raise AuthenticationFailed("invalid credential")


class _FakeResolver:
    def __init__(self, scopes: Mapping[PrincipalId, ProjectScope]) -> None:
        self._scopes = scopes

    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        scope = self._scopes.get(principal_id)
        if scope is None:
            raise ScopeResolutionFailed("no agent_registration for principal")
        return scope


class _FakeQueue:
    def __init__(self) -> None:
        self.enqueued: list[tuple[str, ProjectId, dict[str, object]]] = []

    def enqueue(
        self,
        topic: str,
        project_id: ProjectId,
        payload: Mapping[str, object],
        priority: int = 100,
        available_at: datetime | None = None,
    ) -> int:
        del priority, available_at
        self.enqueued.append((topic, project_id, dict(payload)))
        return len(self.enqueued)


class _FakeInvalidations:
    def __init__(self) -> None:
        self.rows: list[tuple[ProjectId, str, Mapping[str, object] | None]] = []

    def insert_invalidation_event(
        self,
        project_id: ProjectId,
        event_type: str,
        selector: Mapping[str, object] | None = None,
    ) -> uuid.UUID:
        self.rows.append((project_id, event_type, selector))
        return uuid.uuid4()


class _FakeTelemetry:
    def record_retrieval(self, project_id: ProjectId, run_id: RunId, **_: object) -> None:
        del project_id, run_id


class _FakeMemoryReader:
    def __init__(self, rows: Mapping[tuple[ProjectId, MemoryId], MemoryItemRow]) -> None:
        self._rows = rows

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> MemoryItemRow:
        row = self._rows.get((project_id, memory_id))
        if row is None:
            raise NotFound("not found")
        return row


class _FakeExporter:
    def __init__(self, rows: Mapping[ProjectId, list[dict[str, object]]]) -> None:
        self._rows = rows

    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]:
        yield from self._rows.get(project_id, [])


class _UnusedAdmin:
    """Offline probes never call `/admin/projects` or `/admin/agents/register`
    (they need no admin-key bootstrap flow to exercise by-id/export routing),
    so these raise loudly rather than silently no-op if a probe ever does."""

    def create_project(self, name: str, retention_policy: Mapping[str, object] | None = None) -> ProjectId:
        raise NotImplementedError("offline leak fixtures do not provision new projects")

    def create_agent_registration(
        self,
        project_id: ProjectId,
        agent_type_name: str,
        principal_kind: Literal["oidc_sub", "api_key"],
        external_ref: str,
        key_hash: str | None,
    ) -> tuple[PrincipalId, AgentTypeId]:
        raise NotImplementedError("offline leak fixtures do not register agents")


class _UnusedPartitions:
    def create_project_partitions(self, project_id: ProjectId) -> None:
        raise NotImplementedError("offline leak fixtures create no partitions")


class _UnusedKeys:
    def ensure_project_kek(self, project_id: ProjectId) -> None:
        raise NotImplementedError("offline leak fixtures provision no KEKs")


def _fake_memory_row(
    project_id: ProjectId, memory_id: MemoryId, principal_id: PrincipalId, clock: FakeClock
) -> MemoryItemRow:
    text = f"offline leak-suite fake memory row for project {project_id}"
    return MemoryItemRow(
        id=memory_id,
        project_id=project_id,
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.PREFERENCE,
        kind="preference",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.B,
        status=Status.PINNED,
        content=text,
        content_hash=content_hash(text),
        token_count=len(text.split()),
        subject_tag=None,
        q_value=0.5,
        confidence=0.0,
        scored_use_count=0,
        strike_count=0,
        provenance=Provenance(cls=ProvenanceClass.OPERATOR, principal=principal_id),
        scan_verdict_id=uuid.uuid4(),
        schema_version=1,
        created_at=clock.now(),
        status_changed_at=clock.now(),
    )


def _fake_export_rows(project: LeakProject) -> list[dict[str, object]]:
    pid = str(project.scope.project_id.value)
    return [
        {
            "table": "memory_item",
            "row": {
                "id": str(project.memory_id.value),
                "project_id": pid,
                "content": f"offline export row for {pid}",
            },
        },
        {
            "table": "trace_index",
            "row": {
                "run_id": str(project.run_id.value),
                "project_id": pid,
                "payload_ref": project.payload_ref,
            },
        },
        {
            "table": "outcome_event",
            "row": {"event_id": str(project.outcome_event_id), "project_id": pid},
        },
    ]


@pytest.fixture
def offline_two_projects() -> Iterator[tuple[LeakProject, LeakProject, TestClient]]:
    """Two fake, fully in-memory projects and a `TestClient` wired against
    `AppDeps` fakes — zero I/O, runs on any machine, every time (§12).

    Exists so probes 2 ("by-id"), 3 ("admin endpoints"), and 5 ("export") have
    at least one code path that *actually executes* on a build machine with
    no Postgres, instead of only ever reporting SKIPPED-NO-STACK. What it
    proves is narrower than the integration variant — routing/error-shape
    correctness given a scope, not that the scope itself was derived from a
    real, RLS-backed database — and every probe using it says so.
    """
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    principals: dict[str, Principal] = {}
    scopes: dict[PrincipalId, ProjectScope] = {}
    memory_rows: dict[tuple[ProjectId, MemoryId], MemoryItemRow] = {}
    export_rows: dict[ProjectId, list[dict[str, object]]] = {}

    def _build(label: str) -> LeakProject:
        project_id = ProjectId(uuid.uuid4())
        agent_type_id = AgentTypeId(uuid.uuid4())
        principal_id = PrincipalId(uuid.uuid4())
        scope = ProjectScope(
            project_id=project_id, agent_type_id=agent_type_id, principal_id=principal_id
        )
        api_key = f"offline-fake-key-{label}-{uuid.uuid4().hex}"
        principals[api_key] = Principal(
            principal_id=principal_id, kind="api_key", external_ref=f"offline-{label}"
        )
        scopes[principal_id] = scope

        memory_id = MemoryId(uuid.uuid4())
        memory_rows[(project_id, memory_id)] = _fake_memory_row(
            project_id, memory_id, principal_id, clock
        )

        run_id = mint_run_id(now_ms=clock.now_ms())
        payload_ref = f"fs://{project_id}/{run_id}/00000000.tbz"
        outcome_event_id = uuid.uuid4()

        project = LeakProject(
            label=label,
            scope=scope,
            api_key=api_key,
            memory_id=memory_id,
            run_id=run_id,
            payload_ref=payload_ref,
            outcome_event_id=outcome_event_id,
        )
        export_rows[project_id] = _fake_export_rows(project)
        return project

    project_a = _build("a")
    project_b = _build("b")

    deps = AppDeps(
        verifier=_FakeVerifier(principals),
        resolver=_FakeResolver(scopes),
        queue=_FakeQueue(),
        telemetry=_FakeTelemetry(),
        memory_reader=_FakeMemoryReader(memory_rows),
        exporter=_FakeExporter(export_rows),
        invalidations=_FakeInvalidations(),
        admin=_UnusedAdmin(),
        partitions=_UnusedPartitions(),
        keys=_UnusedKeys(),
        clock=clock,
    )
    settings = TracebedSettings(
        storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
        embedding=EmbeddingConfig(model_version="offline-leak-suite"),
    )
    app = create_app(settings, deps)
    with TestClient(app) as client:
        yield project_a, project_b, client


# --------------------------------------------------------------------------- #
# Integration fixtures: a real Postgres, a real Valkey (when reachable), and
# two projects provisioned the way a deployment actually would.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def leak_clock() -> FakeClock:
    return FakeClock(datetime(2026, 1, 1, tzinfo=UTC))


@pytest.fixture(scope="session")
def leak_pg_dsn() -> Iterator[str]:
    """The reachable-DSN probe every other Postgres-backed fixture below
    funnels through — one skip message, matching `tests/conftest.py::pg`."""
    dsn = os.environ.get("TB_STORAGE__PG_DSN")
    if not dsn:
        pytest.skip("TB_STORAGE__PG_DSN is not set -- no Postgres available for the leak suite")
    try:
        with psycopg.connect(dsn, connect_timeout=1):
            pass
    except Exception as exc:
        # Never echo the DSN: it carries the database password (tests/conftest.py::pg's rule).
        pytest.skip(f"Postgres unreachable for the leak suite: {exc.__class__.__name__}")
    yield dsn


@pytest.fixture(scope="session")
def leak_pool(leak_pg_dsn: str) -> Iterator[Any]:
    """A real `ConnectionPool` (contract §5.0: `create_pool`, never a
    `ScopedPool` that does not exist), plus a best-effort attempt to bring
    the schema current.

    CI applies migrations as its own dedicated step before this suite runs
    (`.github/workflows/ci.yml`: "migrate" before "phase 0 gate"); a
    developer pointing `TB_STORAGE__PG_DSN` at a fresh local database still
    gets a working suite because this fixture applies them itself.
    `apply_migrations` is idempotent (returns `[]` once current), so running
    it twice is a no-op, not a hazard. A DSN with DML-only privileges (e.g.
    the `tracebed_app` role, which migrations deliberately cannot use) makes
    this raise on the CREATE TABLE inside 0001 -- skip cleanly rather than
    error, since without schema nothing downstream can run either.
    """
    from tracebed.stores.pg.migrate import apply_migrations

    try:
        apply_migrations(leak_pg_dsn)
    except Exception as exc:
        pytest.skip(
            f"could not bring the Phase 0 schema current for the leak suite: "
            f"{exc.__class__.__name__}"
        )
    pool = create_pool(leak_pg_dsn)
    try:
        yield pool
    finally:
        pool.close()


@pytest.fixture(scope="session")
def leak_repo(leak_pool: Any, leak_clock: FakeClock) -> Repo:
    return Repo(leak_pool, leak_clock)


@pytest.fixture(scope="session")
def leak_queue(leak_pool: Any, leak_clock: FakeClock) -> WorkQueue:
    return WorkQueue(leak_pool, leak_clock, QueueConfig())


@pytest.fixture(scope="session")
def leak_master_key_env() -> Iterator[None]:
    """Ensures `TB_MASTER_KEY` is set for the session so `SubjectKeyManager`
    (needed by `POST /admin/projects`, contract C-14) can construct. Restores
    whatever was there before, and never invents a key when one is already
    configured -- a harness must not silently override a deployment's real
    crypto material."""
    saved = os.environ.get(_MASTER_KEY_ENV)
    if not saved:
        os.environ[_MASTER_KEY_ENV] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(_MASTER_KEY_ENV, None)
        else:
            os.environ[_MASTER_KEY_ENV] = saved


@pytest.fixture(scope="session")
def leak_admin_key_env() -> Iterator[str]:
    """Sets `TB_ADMIN_KEY` for the session -- a random, harness-only value, so
    no operator secret can leak through a passing test run and no real
    deployment's admin key is ever read or logged by this suite."""
    saved = os.environ.get(_ADMIN_KEY_ENV)
    key = "leak-suite-admin-" + secrets.token_urlsafe(24)
    os.environ[_ADMIN_KEY_ENV] = key
    try:
        yield key
    finally:
        if saved is None:
            os.environ.pop(_ADMIN_KEY_ENV, None)
        else:
            os.environ[_ADMIN_KEY_ENV] = saved


@pytest.fixture(scope="session")
def leak_keys_manager(
    leak_repo: Repo, leak_clock: FakeClock, leak_master_key_env: None
) -> SubjectKeyManager:
    del leak_master_key_env
    return SubjectKeyManager(store=leak_repo, master=EnvMasterKeyProvider(), clock=leak_clock)


@pytest.fixture(scope="session")
def leak_settings(leak_pg_dsn: str) -> TracebedSettings:
    return TracebedSettings(
        storage=StorageConfig(pg_dsn=leak_pg_dsn),
        embedding=EmbeddingConfig(model_version="leak-suite"),
    )


@pytest.fixture(scope="session")
def leak_tracestore(tmp_path_factory: pytest.TempPathFactory) -> FsTraceStore:
    return FsTraceStore(tmp_path_factory.mktemp("leak-tracestore"))


@pytest.fixture(scope="session")
def leak_app(
    leak_pool: Any,
    leak_repo: Repo,
    leak_queue: WorkQueue,
    leak_clock: FakeClock,
    leak_settings: TracebedSettings,
    leak_admin_key_env: str,
    leak_keys_manager: SubjectKeyManager,
) -> Any:
    """The real app: real `Repo`, real `WorkQueue`, real `SubjectKeyManager` --
    built the same way `api/main.py::run()` builds it, minus opening a socket.
    """
    del leak_admin_key_env
    principals = _RepoPrincipalLookup(leak_repo)
    verifier = ChainVerifier(
        oidc=None, api_key=ApiKeyVerifier(principals), api_key_mode=True
    )
    deps = AppDeps(
        verifier=verifier,
        resolver=leak_repo,
        queue=leak_queue,
        telemetry=Telemetry(leak_repo, leak_clock),
        memory_reader=leak_repo,
        exporter=leak_repo,
        invalidations=leak_repo,
        admin=leak_repo,
        partitions=_PoolPartitionsAdapter(leak_pool),
        keys=leak_keys_manager,
        clock=leak_clock,
    )
    return create_app(leak_settings, deps)


@pytest.fixture(scope="session")
def leak_client(leak_app: Any) -> Iterator[TestClient]:
    with TestClient(leak_app) as client:
        yield client


def _http_provision_project(client: TestClient, admin_key: str, name: str) -> ProjectId:
    resp = client.post(
        "/admin/projects", json={"name": name}, headers={"X-Admin-Key": admin_key}
    )
    assert resp.status_code == 201, f"provisioning {name!r} failed: {resp.status_code} {resp.text}"
    return ProjectId(uuid.UUID(resp.json()["project_id"]))


def _http_register_agent(
    client: TestClient, admin_key: str, project_id: ProjectId, agent_type: str
) -> tuple[PrincipalId, AgentTypeId, str]:
    resp = client.post(
        "/admin/agents/register",
        json={
            "project_id": str(project_id.value),
            "agent_type": agent_type,
            "principal": {"kind": "api_key"},
        },
        headers={"X-Admin-Key": admin_key},
    )
    assert resp.status_code == 201, f"registering {agent_type!r} failed: {resp.status_code} {resp.text}"
    body = resp.json()
    return (
        PrincipalId(uuid.UUID(body["principal_id"])),
        AgentTypeId(uuid.UUID(body["agent_type_id"])),
        body["api_key"],
    )


def _seed_memory(repo: Repo, clock: FakeClock, scope: ProjectScope) -> MemoryId:
    """One real memory row, inserted through the real scan + state-machine +
    repo path -- never a hand-crafted row (§14 harness DO-NOT list spirit:
    the suite proves what a real write path does, not a shortcut around it).
    """
    content = f"Leak-suite seed preference memory for project {scope.project_id}."
    ctx = ScanContext(
        project_id=scope.project_id,
        mem_type=MemType.PREFERENCE,
        trust_tier=TrustTier.B,
        provenance_class=ProvenanceClass.OPERATOR,
        lane=Lane.OPERATIONAL,
    )
    result = scan(content, context=ctx)
    verdict = result.verdict(clock=clock)

    evidence = TransitionEvidence(
        now=clock.now(),
        provenance_class=ProvenanceClass.OPERATOR,
        trust_tier=TrustTier.B,
        mem_type=MemType.PREFERENCE,
        operator_created=True,
    )
    # PLAN.md §6 defaults -- clear of every invariant-7 floor TransitionLimits enforces.
    limits = TransitionLimits(
        quarantine_ttl_days=30,
        candidate_ttl_days=45,
        promote_min_outcomes=2,
        failure_lesson_outcomes=1,
        promotion_min_distinct_principals=2,
        retire_q_threshold=0.25,
        retire_min_scored_uses=4,
        retire_min_distinct_principals=3,
        archive_floor=0.15,
    )
    status = apply_transition(None, Status.PINNED, evidence, limits)

    item = NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.PREFERENCE,
        kind="preference",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.B,
        status=status,
        content=content,
        token_count=len(content.split()),
        provenance=Provenance(cls=ProvenanceClass.OPERATOR, principal=scope.principal_id),
    )
    return repo.insert_memory_item(scope.project_id, item, verdict)


def _seed_trace(
    repo: Repo,
    clock: FakeClock,
    keys_mgr: SubjectKeyManager,
    store: FsTraceStore,
    scope: ProjectScope,
) -> tuple[RunId, str]:
    """One real trace: encrypted through `SubjectKeyManager`, written through
    `TraceStorePort`, indexed through `Repo.upsert_trace_index` -- the exact
    sequence `ingest.trace_writer` runs, reproduced here because Phase 0 has
    no ingest worker running inside this harness process."""
    run_id = mint_run_id(now_ms=clock.now_ms())
    event = {"type": "run_start", "ts": clock.now().isoformat(), "payload": {}}
    line = canonical_json({"seq": 0, "event": event})
    section = PlainSection(seq_from=0, seq_to=0, subject_tags=(), lines=(line,))
    encrypted = keys_mgr.encrypt(scope.project_id, run_id, [section])
    ref = store.put(scope.project_id, run_id, 0, encrypted.to_bytes())

    repo.upsert_trace_index(
        scope.project_id,
        TraceIndexUpsert(
            run_id=run_id,
            agent_type_id=scope.agent_type_id,
            workflow_template_id=None,
            submitter_principal=scope.principal_id,
            input_signature_hash=bytes(40),
            instrumentation_source=InstrumentationSource.SDK,
            path={"payload_refs": [str(ref)]},
            started_at=clock.now(),
            ended_at=None,
            payload_ref=str(ref),
            outcome_status=TraceOutcomeStatus.PENDING,
        ),
    )
    return run_id, str(ref)


def _seed_outcome(repo: Repo, clock: FakeClock, scope: ProjectScope, run_id: RunId) -> uuid.UUID:
    event_id = uuid.uuid4()
    repo.insert_outcome_event(
        scope.project_id,
        OutcomeEventInsert(
            event_id=event_id,
            run_id=run_id,
            principal_id=scope.principal_id,
            adapter=AdapterClass.IMPLICIT,
            r=0.0,
            w_zero=True,
            payload={},
            occurred_at=clock.now(),
            arrived_at=clock.now(),
        ),
    )
    return event_id


def _provision_leak_project(
    client: TestClient,
    admin_key: str,
    repo: Repo,
    clock: FakeClock,
    keys_mgr: SubjectKeyManager,
    store: FsTraceStore,
    label: str,
) -> LeakProject:
    project_id = _http_provision_project(client, admin_key, f"leak-suite-{label}-{uuid.uuid4().hex[:8]}")
    principal_id, _agent_type_id, api_key = _http_register_agent(
        client, admin_key, project_id, f"leak-agent-{label}"
    )
    scope = repo.resolve_project(principal_id)
    memory_id = _seed_memory(repo, clock, scope)
    run_id, payload_ref = _seed_trace(repo, clock, keys_mgr, store, scope)
    outcome_event_id = _seed_outcome(repo, clock, scope, run_id)
    return LeakProject(
        label=label,
        scope=scope,
        api_key=api_key,
        memory_id=memory_id,
        run_id=run_id,
        payload_ref=payload_ref,
        outcome_event_id=outcome_event_id,
    )


@pytest.fixture(scope="session")
def two_leak_projects(
    leak_client: TestClient,
    leak_admin_key_env: str,
    leak_repo: Repo,
    leak_clock: FakeClock,
    leak_keys_manager: SubjectKeyManager,
    leak_tracestore: FsTraceStore,
) -> tuple[LeakProject, LeakProject]:
    """THE leak-suite fixture (mirrors what contract §13.1 asks
    `tests/phase0/conftest.py::two_projects` for, built from this chunk's own
    file list instead): two real, fully-provisioned projects -- registry row,
    partitions, project KEK, a registered `api_key` principal, one memory
    item, one trace (index row + encrypted payload on disk), one outcome
    event -- each distinct per test session (fresh UUIDs every run) so a
    leaked row from a previous run can never be mistaken for a passing probe.
    """
    project_a = _provision_leak_project(
        leak_client, leak_admin_key_env, leak_repo, leak_clock, leak_keys_manager, leak_tracestore, "a"
    )
    project_b = _provision_leak_project(
        leak_client, leak_admin_key_env, leak_repo, leak_clock, leak_keys_manager, leak_tracestore, "b"
    )
    return project_a, project_b


# --------------------------------------------------------------------------- #
# Valkey.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def leak_valkey_url() -> Iterator[str]:
    url = os.environ.get("TB_STORAGE__VALKEY_URL")
    if not url:
        pytest.skip("TB_STORAGE__VALKEY_URL is not set -- no Valkey available for the leak suite")
    from valkey import Valkey

    try:
        probe = Valkey.from_url(url, socket_connect_timeout=1, socket_timeout=1)
        probe.ping()
        probe.close()
    except Exception as exc:
        pytest.skip(f"Valkey unreachable for the leak suite: {exc.__class__.__name__}")
    yield url


@pytest.fixture(scope="session")
def leak_valkey(leak_valkey_url: str) -> Iterator[Any]:
    from tracebed.stores.valkey.client import ValkeyClient

    client = ValkeyClient.from_url(leak_valkey_url)
    try:
        yield client
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# RLS bypass probe support (probe 7). `PARTITIONED_TABLES` is imported from
# `stores.pg.ddl`, never re-typed, so a new partitioned table cannot be
# forgotten by this file (PHASE-0 Task 17's own instruction).
# --------------------------------------------------------------------------- #

# One syntactically-valid seed row per partitioned table, keyed by table name.
# Mirrors `tests/phase0/test_partitions.py::_SEED_ROWS` (migrations chunk) --
# duplicated deliberately (§13.1: chunk-local fakes/fixtures are accepted
# duplication, not a merge collision) so this file has no import dependency
# on a test module owned by another chunk.
SEED_ROW_SQL: dict[str, str] = {
    "memory_item": (
        "INSERT INTO memory_item (id, project_id, scope_type, mem_type, kind, lane,"
        " trust_tier, status, content, content_hash, token_count, provenance,"
        " scan_verdict_id) VALUES (gen_random_uuid(), %(pid)s, 'project_shared',"
        " 'lesson', 'note', 'operational', 'B', 'quarantined', 'rls-probe-seed', 'h', 1,"
        " '{}'::jsonb, gen_random_uuid())"
    ),
    "memory_link": (
        "INSERT INTO memory_link (project_id, src_id, dst_id, relation)"
        " VALUES (%(pid)s, gen_random_uuid(), gen_random_uuid(), 'related')"
    ),
    "derived_state": (
        "INSERT INTO derived_state (project_id, agent_type_id, key, version, value)"
        " VALUES (%(pid)s, gen_random_uuid(), 'rls-probe-seed', 1, '{}'::jsonb)"
    ),
    "trace_index": (
        "INSERT INTO trace_index (run_id, project_id, agent_type_id, submitter_principal,"
        " input_signature_hash, instrumentation_source)"
        " VALUES (gen_random_uuid(), %(pid)s, gen_random_uuid(), gen_random_uuid(),"
        " '\\x00'::bytea, 'sdk')"
    ),
    "trace_subject": (
        "INSERT INTO trace_subject (run_id, project_id, subject_tag)"
        " VALUES (gen_random_uuid(), %(pid)s, 'rls-probe:seed')"
    ),
    "subject_key": (
        "INSERT INTO subject_key (project_id, subject_tag, key_id, wrapped_kek)"
        " VALUES (%(pid)s, 'rls-probe:seed', gen_random_uuid(), '\\x00'::bytea)"
    ),
    "outcome_event": (
        "INSERT INTO outcome_event (event_id, run_id, project_id, principal_id, adapter, r)"
        " VALUES (gen_random_uuid(), gen_random_uuid(), %(pid)s, gen_random_uuid(),"
        " 'verdict', 1.0)"
    ),
    "injection_log": (
        "INSERT INTO injection_log (run_id, project_id, memory_id, slot, score, tokens)"
        " VALUES (gen_random_uuid(), %(pid)s, gen_random_uuid(), 'fact', 0.5, 10)"
    ),
    "retrieval_event": (
        "INSERT INTO retrieval_event (run_id, project_id, outcome_code, latency_ms, arm)"
        " VALUES (gen_random_uuid(), %(pid)s, 'empty_result', 5, 'memory_on')"
    ),
    # author_agent is uuid NOT NULL and value_ref/status are NOT NULL
    # (migrations/0002_partitioned.sql), so this seed supplies all three rather
    # than relying on columns that used to be nullable.
    "blackboard_entry": (
        "INSERT INTO blackboard_entry"
        " (project_id, run_id, branch_id, author_agent, key, value_ref, status)"
        " VALUES (%(pid)s, gen_random_uuid(), 'main', gen_random_uuid(), 'k',"
        " 'rls-probe-seed-ref', 'committed')"
    ),
    "invalidation_event": (
        "INSERT INTO invalidation_event (project_id, event_type) VALUES (%(pid)s, 'rls-probe-seed')"
    ),
    "spend_ledger": (
        "INSERT INTO spend_ledger (project_id, day, worker, model_id)"
        " VALUES (%(pid)s, CURRENT_DATE, 'rls-probe-seed', 'm')"
    ),
    "review_queue": (
        "INSERT INTO review_queue (project_id, reason) VALUES (%(pid)s, 'rls-probe-seed')"
    ),
    # memory_status_log: the 14th partitioned table (migrations/0004_lifecycle.sql), added to
    # PARTITIONED_TABLES after this fixture was first written. `from_status <> to_status` is a
    # table CHECK; history_id/reason/evidence/changed_at all default. Without this seed the
    # probe-7 fixture aborts on `seed_all_partitioned_tables`'s completeness assertion before it
    # can make its RLS claim, leaving the cross-project wall unverified.
    "memory_status_log": (
        "INSERT INTO memory_status_log (project_id, memory_id, from_status, to_status)"
        " VALUES (%(pid)s, gen_random_uuid(), 'quarantined', 'candidate')"
    ),
}


def seed_all_partitioned_tables(pool: Any, project_id: ProjectId) -> None:
    """One extra row in EVERY partitioned table for `project_id`, so probe 7's
    "zero rows" claim is a claim about a database that demonstrably has rows
    -- an empty table returning zero rows proves nothing about RLS.
    Enumerates `PARTITIONED_TABLES` from `stores.pg.ddl` so a table added
    after this file was written is still seeded (Task 17's own instruction).
    """
    missing = set(PARTITIONED_TABLES) - set(SEED_ROW_SQL)
    if missing:
        raise AssertionError(
            f"seed_all_partitioned_tables: no seed row defined for {sorted(missing)} -- "
            "a partitioned table was added without updating this harness fixture"
        )
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('tracebed.project_id', %(pid)s, true)",
                {"pid": str(project_id.value)},
            )
            for table in PARTITIONED_TABLES:
                cur.execute(SEED_ROW_SQL[table], {"pid": str(project_id.value)})
        conn.commit()


@pytest.fixture(scope="session")
def leak_rls_seeded(
    leak_pool: Any, two_leak_projects: tuple[LeakProject, LeakProject]
) -> tuple[LeakProject, LeakProject]:
    """`two_leak_projects`, plus one extra guaranteed row per partitioned
    table for each project (some tables -- memory_link, derived_state,
    blackboard_entry, invalidation_event, spend_ledger, review_queue -- are
    never written by anything else in Phase 0, so without this the RLS probe
    would vacuously pass against empty tables)."""
    project_a, project_b = two_leak_projects
    seed_all_partitioned_tables(leak_pool, project_a.scope.project_id)
    seed_all_partitioned_tables(leak_pool, project_b.scope.project_id)
    return project_a, project_b


def app_role_conninfo(pg_dsn: str) -> str:
    """`pg_dsn` with credentials swapped for the non-owner, non-BYPASSRLS
    `tracebed_app` role (contract §14: RLS FORCE is meaningless if every
    probe connects as the table owner). Uses psycopg's own conninfo parser
    so this works for both URL- and keyword-style DSNs."""
    from psycopg.conninfo import make_conninfo

    return make_conninfo(pg_dsn, user="tracebed_app", password=APP_ROLE_PASSWORD)
