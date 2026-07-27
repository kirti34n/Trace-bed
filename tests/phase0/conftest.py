"""Phase 0 fixtures that need a live stack (PHASE0-CONTRACT.md §13.1).

Layered on top of `tests/conftest.py` rather than duplicating it: that file owns
the pure fixtures (`fake_clock`, `settings`, `tracestore_root`) and the single
"is Postgres reachable" probe (`pg`). Everything here builds on `pg`, so there
is exactly one place that decides whether a database exists and exactly one skip
message when it does not.

ENVIRONMENT CONSTRAINT: this repository was authored on a machine with no
Docker. Every fixture below therefore skips cleanly rather than erroring — a
test that errors at setup is a red gate, and a red gate that means "no database
here" is indistinguishable from a red gate that means "the isolation test
failed". Those two must never look alike.

INTEGRATION AUDIT (C-27): as merged, `pg_pool` constructed a `ScopedPool` class
that `stores.pg.pool` does not define (it exports `create_pool`/`scoped`), and
`work_queue` called `WorkQueue(pool, clock)` where `WorkQueue.__init__` requires
three arguments. Both were invisible on a machine with no Postgres — the `pg`
probe skips before either body runs — and both would have turned every
integration test in five modules into a setup ERROR the moment a database became
reachable, i.e. the exact indistinguishable-red-gate failure the paragraph above
forbids. `two_projects`, the fixture §13.1 calls "THE leak-suite fixture", was
missing outright, so `test_queue.py` / `test_migrations.py` / `test_partitions.py`
would have failed fixture lookup as well.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import QueueConfig
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, uuid7
from tracebed.domain.scope import ProjectScope

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool

    from tracebed.stores.pg.repo import Repo


@pytest.fixture
def pg_dsn(pg: str) -> str:
    """Alias for the reachable-DSN probe, under the name §13.1 gives it."""
    return pg


@pytest.fixture(scope="session")
def _pg_pools() -> Iterator[dict[str, ConnectionPool]]:
    """Session-lifetime registry of open pools, keyed by DSN.

    §13.1 requires "migrations applied once per session", which a
    function-scoped fixture cannot express on its own — and `pg_pool` MUST stay
    function-scoped because it descends from `tests/conftest.py::pg`, which is
    function-scoped and is the single skip point this module is built around.
    Caching the pool here gives both: one pool and one migration run per DSN per
    session, with the skip decision still taken per test.
    """
    pools: dict[str, ConnectionPool] = {}
    try:
        yield pools
    finally:
        for pool in pools.values():
            pool.close()


@pytest.fixture
def pg_pool(pg_dsn: str, _pg_pools: dict[str, ConnectionPool]) -> ConnectionPool:
    """A `psycopg_pool.ConnectionPool` against the live database (§13.1, §5.0).

    `Repo.__init__` and `WorkQueue.__init__` both take this exact type
    (contract §5.0); `stores.pg.pool` deliberately exposes no pool *wrapper*
    class, because `scoped()` — not a bespoke pool object — is the structural
    gateway to the RLS GUC.

    Imported lazily so this module still collects on a machine where psycopg
    cannot open a connection at import time.
    """
    if pg_dsn not in _pg_pools:
        from tracebed.stores.pg.migrate import apply_migrations
        from tracebed.stores.pg.pool import create_pool

        try:
            # Idempotent: a second call against a current schema applies nothing.
            # A DSN with DML-only rights (the `tracebed_app` role, which
            # migrations deliberately cannot use) raises here — skip, because
            # without a schema nothing downstream can run either. Never error.
            apply_migrations(pg_dsn)
        except Exception as exc:
            pytest.skip(f"could not bring the Phase 0 schema current: {exc.__class__.__name__}")
        _pg_pools[pg_dsn] = create_pool(pg_dsn)
    return _pg_pools[pg_dsn]


@pytest.fixture
def repo(pg_pool: ConnectionPool, fake_clock: FakeClock) -> Repo:
    """The typed repository under the Phase 0 epoch clock."""
    from tracebed.stores.pg.repo import Repo

    return Repo(pg_pool, fake_clock)


@pytest.fixture
def work_queue(pg_pool: ConnectionPool, fake_clock: FakeClock) -> Any:
    """`WorkQueue(pool, clock, QueueConfig())` — three arguments, per §5.3/§13.1."""
    from tracebed.stores.pg.queue import WorkQueue

    return WorkQueue(pg_pool, fake_clock, QueueConfig())


@pytest.fixture
def valkey_url() -> Iterator[str]:
    """A reachable Valkey URL, or a clean `pytest.skip` (§13.1).

    Mirrors `tests/conftest.py::pg` exactly: one probe, one skip message, and
    the connection attempt happens at fixture setup — never at import or
    collection time (§12).
    """
    url = os.environ.get("TB_STORAGE__VALKEY_URL")
    if not url:
        pytest.skip("TB_STORAGE__VALKEY_URL is not set — no Valkey available")

    try:
        from valkey import Valkey
    except ImportError:  # pragma: no cover - valkey is a hard dependency
        pytest.skip("valkey is not importable — no Valkey available")

    try:
        probe = Valkey.from_url(url, socket_connect_timeout=1, socket_timeout=1)
        probe.ping()
        probe.close()
    except Exception as exc:
        # Never echo the URL: it can carry a password, and a skip message lands
        # verbatim in the gate report and in CI logs.
        pytest.skip(f"Valkey unreachable (TB_STORAGE__VALKEY_URL): {exc.__class__.__name__}")

    yield url


@pytest.fixture
def s3_config() -> dict[str, str]:
    """S3/MinIO endpoint + credentials, or a clean `pytest.skip` (§13.1).

    Returns the mapping `stores.tracestore.s3.S3TraceStore` needs rather than a
    constructed store, so a test can build the store with its own bucket/prefix
    without this fixture guessing one.
    """
    endpoint = os.environ.get("TB_S3_ENDPOINT")
    if not endpoint:
        pytest.skip("TB_S3_ENDPOINT is not set — no object store available")

    access_key = os.environ.get("TB_S3_ACCESS_KEY")
    secret_key = os.environ.get("TB_S3_SECRET_KEY")
    if not access_key or not secret_key:
        pytest.skip("TB_S3_ACCESS_KEY / TB_S3_SECRET_KEY are not set — no object store available")

    import socket
    from urllib.parse import urlsplit

    # A TCP connect, not an HTTP request: reachability is the only question
    # here, and `urlopen` on a caller-supplied endpoint would accept `file:`
    # and other non-network schemes (ruff S310) — a probe must not be a way to
    # read the local filesystem.
    parsed = urlsplit(endpoint)
    host = parsed.hostname
    if host is None:
        pytest.skip("TB_S3_ENDPOINT is not a URL with a host — no object store available")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=1):
            pass
    except OSError as exc:
        pytest.skip(f"S3 endpoint unreachable (TB_S3_ENDPOINT): {exc.__class__.__name__}")

    return {
        "endpoint": endpoint,
        "access_key": access_key,
        "secret_key": secret_key,
        "region": os.environ.get("TB_S3_REGION", "us-east-1"),
        "bucket": os.environ.get("TB_S3_BUCKET", "tracebed-test"),
    }


@pytest.fixture
def project_a() -> ProjectId:
    """Project A of the two-project leak fixture. Distinct per test run so a
    leaked row from a previous run cannot be mistaken for a passing isolation test."""
    return ProjectId(uuid7())


@pytest.fixture
def project_b() -> ProjectId:
    return ProjectId(uuid7())


@pytest.fixture
def scope_a(project_a: ProjectId) -> ProjectScope:
    return ProjectScope(
        project_id=project_a,
        agent_type_id=AgentTypeId(uuid7()),
        principal_id=PrincipalId(uuid7()),
    )


@pytest.fixture
def scope_b(project_b: ProjectId) -> ProjectScope:
    return ProjectScope(
        project_id=project_b,
        agent_type_id=AgentTypeId(uuid7()),
        principal_id=PrincipalId(uuid7()),
    )


def _provision(repo: Repo, pool: ConnectionPool, label: str) -> ProjectScope:
    """One real project: registry row, partitions, agent type, registered
    `api_key` principal — then the scope read back through `resolve_project`.

    Reading the scope back rather than assembling it from the ids we just
    minted is the point: it is the same derivation path the API uses
    (authenticate -> `resolve_project` -> `ProjectScope`), so a test that
    passes here is testing the real scope-derivation, not a hand-built triple
    that happens to hold the right UUIDs.
    """
    from tracebed.stores.pg.partitions import create_project_partitions

    suffix = uuid.uuid4().hex[:8]
    project_id = repo.create_project(f"phase0-conftest-{label}-{suffix}")
    with pool.connection() as conn:
        create_project_partitions(conn, project_id)
    agent_type_id = repo.create_agent_type(project_id, f"conftest-agent-{label}-{suffix}")
    principal_id = repo.create_principal(
        "api_key", f"conftest-{label}-{uuid.uuid4().hex}", "conftest-not-a-real-key-hash"
    )
    repo.register_agent(project_id, principal_id, agent_type_id)
    return repo.resolve_project(principal_id)


@pytest.fixture
def two_projects(repo: Repo, pg_pool: ConnectionPool) -> tuple[ProjectScope, ProjectScope]:
    """THE leak-suite fixture (§13.1): two fully-provisioned projects, A and B.

    Integration-only by construction — it descends from `pg_pool`, so on a
    machine with no database it skips with the one Postgres message rather than
    erroring. Fresh UUIDs every test, so a row leaked by an earlier run can
    never be mistaken for a passing isolation assertion.

    Partitions are deliberately NOT dropped at teardown: `drop_project` is
    itself under test (`test_partitions.py`), and a teardown that silently
    removed the evidence would hide a partition that was never created. CI runs
    against an ephemeral database; a developer's local database accumulates
    partitions, which is the correct trade for not destroying evidence.
    """
    return _provision(repo, pg_pool, "a"), _provision(repo, pg_pool, "b")
