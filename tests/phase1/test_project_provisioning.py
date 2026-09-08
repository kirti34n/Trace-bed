"""Offline and isolated-owner checks for atomic project provisioning."""

from __future__ import annotations

import copy
import os
import shutil
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

import psycopg
import pytest

from tracebed.crypto.subject_digest import subject_digest
from tracebed.domain.clock import FakeClock, SystemClock
from tracebed.domain.errors import ProjectProvisioningConflict
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg import bootstrap, provisioning
from tracebed.stores.pg.ddl import PARTITIONED_TABLES, partition_name
from tracebed.stores.pg.migrate import apply_migrations, current_revision
from tracebed.stores.pg.pool import create_pool

pytestmark = pytest.mark.phase1


class _Master:
    def master_key(self) -> bytes:
        return b"m" * 32


@dataclass
class _Database:
    projects: dict[str, dict[str, object]] = field(default_factory=dict)
    subject_keys: dict[tuple[str, str], dict[str, object]] = field(default_factory=dict)
    partitions: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


class _Cursor:
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection
        self._result: dict[str, object] | None = None

    def execute(self, query: str, params: dict[str, object] | None = None) -> None:
        params = params or {}
        self._connection.queries.append(query)
        if query == provisioning._LOCK_SQL:
            self._connection._db.lock.acquire()
            self._connection._holds_lock = True
        elif query == provisioning._EXISTING_SQL:
            self._result = self._connection._db.projects.get(str(params["key_hash"]))
        elif query == provisioning._INSERT_PROJECT_SQL:
            project_id = params["project_id"]
            assert isinstance(project_id, ProjectId)
            self._connection._db.projects[str(params["key_hash"])] = {
                "project_id": project_id.value,
                "provisioning_request_hash": params["request_hash"],
            }
        elif query == provisioning._SET_PROJECT_SCOPE_SQL:
            self._connection.project_scope = str(params["project_id"])
            self._connection.scope_values.append(self._connection.project_scope)
        elif query == provisioning._GET_SUBJECT_KEY_SQL:
            self._result = self._connection._db.subject_keys.get(
                (str(params["project_id"]), str(params["subject_tag"]))
            )
        elif query == provisioning._GET_SUBJECT_KEY_BY_DIGEST_SQL:
            self._result = next(
                (
                    row
                    for (project_id, _tag), row in self._connection._db.subject_keys.items()
                    if project_id == str(params["project_id"])
                    and row["subject_digest"] == params["subject_digest"]
                ),
                None,
            )
        else:
            raise AssertionError(f"unexpected cursor SQL: {query}")

    def fetchone(self) -> dict[str, object] | None:
        return self._result

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _Connection:
    def __init__(self, database: _Database) -> None:
        self._db = database
        self._holds_lock = False
        self._snapshot: (
            tuple[dict[str, dict[str, object]], dict[tuple[str, str], dict[str, object]], list[str]]
            | None
        ) = None
        self.queries: list[str] = []
        self.fail_subject_key_insert = False
        self.project_scope: str | None = None
        self.scope_values: list[str] = []

    def cursor(self, **_: object) -> _Cursor:
        return _Cursor(self)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        outermost = self._snapshot is None
        if outermost:
            self._snapshot = (
                copy.deepcopy(self._db.projects),
                copy.deepcopy(self._db.subject_keys),
                list(self._db.partitions),
            )
        try:
            yield
        except Exception:
            if outermost and self._snapshot is not None:
                self._db.projects, self._db.subject_keys, self._db.partitions = self._snapshot
            raise
        finally:
            if outermost:
                self._snapshot = None
                self.project_scope = None
                if self._holds_lock:
                    self._holds_lock = False
                    self._db.lock.release()

    def execute(self, query: str, params: dict[str, object]) -> None:
        self.queries.append(query)
        if query not in (
            provisioning._INSERT_SUBJECT_KEY_SQL,
            provisioning._INSERT_SUBJECT_KEY_V2_SQL,
        ):
            raise AssertionError(f"unexpected direct SQL: {query}")
        if self.fail_subject_key_insert:
            raise RuntimeError("injected KEK write failure")
        subject_tag = params.get("subject_tag")
        self._db.subject_keys[(str(params["project_id"]), str(subject_tag))] = {
            "subject_tag": subject_tag,
            "subject_digest": params["subject_digest"],
            "wrap_version": 2 if query == provisioning._INSERT_SUBJECT_KEY_V2_SQL else 1,
            "key_id": params["key_id"],
            "wrapped_kek": params["wrapped_kek"],
            "created_at": params["created_at"],
            "destroyed_at": None,
        }


class _Pool:
    def __init__(self, database: _Database) -> None:
        self._database = database
        self.connections: list[_Connection] = []

    @contextmanager
    def connection(self) -> Iterator[_Connection]:
        connection = _Connection(self._database)
        self.connections.append(connection)
        yield connection


def _provisioner(database: _Database) -> tuple[provisioning.ProjectProvisioner, _Pool]:
    pool = _Pool(database)
    return (
        provisioning.ProjectProvisioner(
            pool,  # type: ignore[arg-type]
            _Master(),
            FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        ),
        pool,
    )


def _create_partitions(connection: _Connection, project_id: ProjectId) -> None:
    connection._db.partitions.append(str(project_id))


def test_exact_replay_returns_one_project_with_one_registry_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    provisioner, pool = _provisioner(database)
    monkeypatch.setattr(provisioning, "create_project_partitions", _create_partitions)

    first = provisioner.provision_project(
        name="acme",
        retention_policy={"days": 90},
        idempotency_key_hash="key",
        request_hash="request",
    )
    replay = provisioner.provision_project(
        name="acme",
        retention_policy={"days": 90},
        idempotency_key_hash="key",
        request_hash="request",
    )

    assert replay == first
    assert len(database.projects) == len(database.partitions) == 1
    assert (str(first), "__project__") in database.subject_keys
    assert provisioning._LOCK_SQL in pool.connections[0].queries
    assert provisioning._SET_PROJECT_SCOPE_SQL in pool.connections[0].queries
    assert pool.connections[0].scope_values == [str(first)]
    assert pool.connections[0].project_scope is None
    key = database.subject_keys[(str(first), "__project__")]
    assert key["subject_digest"] == subject_digest(first, "__project__")
    assert key["wrap_version"] == 1


def test_changed_request_for_an_existing_key_is_a_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    provisioner, _ = _provisioner(database)
    monkeypatch.setattr(provisioning, "create_project_partitions", _create_partitions)
    provisioner.provision_project(
        name="acme", retention_policy=None, idempotency_key_hash="key", request_hash="first"
    )

    with pytest.raises(ProjectProvisioningConflict):
        provisioner.provision_project(
            name="other", retention_policy=None, idempotency_key_hash="key", request_hash="changed"
        )


def test_kek_failure_rolls_back_registry_partitions_and_idempotency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    provisioner, pool = _provisioner(database)
    monkeypatch.setattr(provisioning, "create_project_partitions", _create_partitions)

    original_connection = pool.connection

    @contextmanager
    def failing_connection() -> Iterator[_Connection]:
        with original_connection() as connection:
            connection.fail_subject_key_insert = True
            yield connection

    monkeypatch.setattr(pool, "connection", failing_connection)
    with pytest.raises(RuntimeError, match="KEK write failure"):
        provisioner.provision_project(
            name="acme", retention_policy=None, idempotency_key_hash="key", request_hash="request"
        )

    assert database.projects == {}
    assert database.subject_keys == {}
    assert database.partitions == []


def test_concurrent_same_key_returns_one_project_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _Database()
    provisioner, _ = _provisioner(database)
    monkeypatch.setattr(provisioning, "create_project_partitions", _create_partitions)
    barrier = threading.Barrier(2)
    results: list[ProjectId] = []

    def create() -> None:
        barrier.wait()
        results.append(
            provisioner.provision_project(
                name="acme",
                retention_policy=None,
                idempotency_key_hash="same",
                request_hash="request",
            )
        )

    first = threading.Thread(target=create)
    second = threading.Thread(target=create)
    first.start()
    second.start()
    first.join()
    second.join()

    assert results == [results[0], results[0]]
    assert len(database.projects) == 1


def test_project_provisioner_uses_its_given_admin_pool_only() -> None:
    database = _Database()
    provisioner, pool = _provisioner(database)
    assert cast(object, provisioner._pool) is pool


_AUTHORITY_PG18_IMAGE = (
    "tensorchord/vchord-suite@"
    "sha256:c6e5e77a1180199f91b040b6e85c6d10b0ded6d49fb614dfd2e7272ffb91af08"
)
_AUTHORITY_OWNER_PASSWORD = "tracebed-phase1-provisioning-test-owner"


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one fixed Docker command for the test-owned disposable PG18."""

    docker = shutil.which("docker")
    if docker is None:  # pragma: no cover - fixture turns this into a skip
        raise RuntimeError("Docker is unavailable")
    return subprocess.run(  # noqa: S603 -- fixed executable and test-owned arguments
        [docker, *args], check=check, text=True, capture_output=True
    )


def _attested_owner_dsn(dsn: str) -> str:
    """Add only the authority migration runner's fixed test attestations."""

    return bootstrap._dedicated_cluster_dsn(dsn, "dedicated", ingress_quarantined=True)


def _apply_through_0010(dsn: str) -> None:
    """Build the staged baseline without bypassing the c11 gate."""

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(dsn)
    assert current_revision(dsn)[0] == "0010_authority_foundation"


def _prepare_disposable_c12_owner(dsn: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Prepare c12 on a test-owned cluster through the supported owner path.

    This is intentionally the same staged owner/bootstrap sequence used by
    the authority cutover integration suite.  It is not an arbitrary table
    owner or a synthetic privilege grant: the resulting owner connection is
    the supported project-provisioning boundary.
    """

    _apply_through_0010(dsn)
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_app NOINHERIT PASSWORD 'legacy-password'")
    assert apply_migrations(_attested_owner_dsn(dsn), through="0011_authority_cutover") == [
        "0011_authority_cutover"
    ]

    # Bootstrap normally invokes the general migration runner before it
    # publishes c11.  The c11 migration is already complete here; retaining
    # that no-op boundary avoids an ineligible c12 attempt before admission
    # has been explicitly closed.
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_owner_dsn(dsn)) == ["0012_erasure_saga"]

    # E1 intentionally has no serving erasure runtime.  This owner-only test
    # setup performs its later publication hook solely so the c12 activity
    # marker accepts the supported owner provisioning transaction.
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state "
            "SET activated_at = clock_timestamp() WHERE singleton"
        )


@pytest.fixture
def disposable_c12_owner_dsn(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Yield a fully isolated owner/bootstrap c12 database and remove it whole."""

    if os.environ.get("TB_0011_DOCKER_LIVE") != "1":
        pytest.skip("set TB_0011_DOCKER_LIVE=1 for isolated authority PG18")
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable for isolated authority PG18")
    if _docker("image", "inspect", _AUTHORITY_PG18_IMAGE, check=False).returncode != 0:
        pytest.skip("the pinned authority PG18 image is not available locally")

    name = f"tracebed-phase1-provisioning-{uuid.uuid4().hex}"
    _docker(
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-e",
        "POSTGRES_USER=tracebed_owner",
        "-e",
        f"POSTGRES_PASSWORD={_AUTHORITY_OWNER_PASSWORD}",
        "-e",
        "POSTGRES_DB=tracebed",
        "-p",
        "127.0.0.1::5432",
        _AUTHORITY_PG18_IMAGE,
    )
    try:
        for _ in range(40):
            if (
                _docker(
                    "exec",
                    name,
                    "pg_isready",
                    "-U",
                    "tracebed_owner",
                    "-d",
                    "tracebed",
                    check=False,
                ).returncode
                == 0
            ):
                break
            time.sleep(0.25)
        else:
            pytest.fail("isolated authority PG18 did not become ready")
        port = _docker("port", name, "5432/tcp").stdout.strip().rsplit(":", 1)[-1]
        assert port.isdecimal()
        dsn = f"postgresql://tracebed_owner:{_AUTHORITY_OWNER_PASSWORD}@127.0.0.1:{port}/tracebed"
        for _ in range(20):
            try:
                with psycopg.connect(dsn, connect_timeout=1):
                    pass
            except psycopg.OperationalError:
                time.sleep(0.25)
            else:
                break
        else:
            pytest.fail("isolated authority PG18 is not reachable")
        _prepare_disposable_c12_owner(dsn, monkeypatch)
        yield dsn
    finally:
        _docker("rm", "-f", name, check=False)


@pytest.mark.integration
def test_owner_bootstrap_provisioner_creates_22_leaves_and_resets_scope(
    disposable_c12_owner_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supported owner/bootstrap path provisions atomically on c12.

    The test owns the entire container and deletes it afterwards.  It never
    mutates a retained database's relation ownership, grants extension
    privileges to an arbitrary role, or deletes a project as cleanup.
    """

    owner_pool = create_pool(disposable_c12_owner_dsn, min_size=1, max_size=1)
    try:
        provisioner = provisioning.ProjectProvisioner(owner_pool, _Master(), SystemClock())
        first = provisioner.provision_project(
            name="supported-owner-provisioning",
            retention_policy=None,
            idempotency_key_hash=uuid.uuid4().hex,
            request_hash=uuid.uuid4().hex,
        )

        with psycopg.connect(disposable_c12_owner_dsn) as owner:
            key = owner.execute(
                "SELECT wrapped_kek FROM subject_key "
                "WHERE project_id = %s AND subject_tag = '__project__'",
                (first.value,),
            ).fetchone()
            assert key is not None and len(bytes(key[0])) > 0
            leaves = owner.execute(
                "SELECT parent.relname, child.relname "
                "FROM pg_inherits AS inheritance "
                "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
                "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
                "WHERE parent.relname = ANY(%s) "
                "ORDER BY parent.relname, child.relname",
                (list(PARTITIONED_TABLES),),
            ).fetchall()
            assert leaves == sorted(
                (parent, partition_name(parent, first)) for parent in PARTITIONED_TABLES
            )

        failure_key = uuid.uuid4().hex

        def fail_after_scope(conn: object, project_id: ProjectId) -> None:
            del conn, project_id
            raise RuntimeError("injected partition failure")

        monkeypatch.setattr(provisioning, "create_project_partitions", fail_after_scope)
        with pytest.raises(RuntimeError, match="injected partition failure"):
            provisioner.provision_project(
                name="supported-owner-provisioning-failure",
                retention_policy=None,
                idempotency_key_hash=failure_key,
                request_hash=uuid.uuid4().hex,
            )
        with psycopg.connect(disposable_c12_owner_dsn) as owner:
            assert owner.execute(
                "SELECT count(*) FROM project WHERE provisioning_key_hash = %s", (failure_key,)
            ).fetchone() == (0,)

        with owner_pool.connection() as conn, conn.transaction():
            scope = conn.execute("SELECT current_setting('tracebed.project_id', true)").fetchone()
            assert scope is not None and scope[0] in (None, "")
    finally:
        owner_pool.close()
