"""Pinned-PG18 E3 request, receipt, recovery, and project-tombstone evidence.

The source distribution intentionally creates no erasure login.  This suite
creates one temporary direct group member inside the isolated container, then
drops it again.  It therefore proves the real SECURITY DEFINER boundary
without claiming a deployable production identity.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg_pool import ConnectionPool

from tests.phase3.test_authority_cutover_live import (
    _OWNER_PASSWORD,
    _apply_through_0010,
    _attested_dsn,
    _create_active_project_admin,
    _harden_legacy_role_for_cutover,
    _role_dsn,
)
from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Arm, OutcomeCode, ProjectRole, Slot
from tracebed.domain.errors import ErasureClosureChanged, RetrievalAuditUnavailable
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.erasure.domain import ErasureLease
from tracebed.stores.pg import bootstrap
from tracebed.stores.pg.activity import ActivityGate, create_activity_pool
from tracebed.stores.pg.authority import AuthorizedRetrievalOpener
from tracebed.stores.pg.erasure_executor import PgErasureExecutorStore
from tracebed.stores.pg.migrate import apply_migrations, current_revision
from tracebed.stores.pg.partitions import (
    PARTITIONED_TABLES,
    create_project_partitions,
    ensure_schema_current,
    partition_name,
)
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.rows import InjectionRow, RetrievalEventInsert

pytestmark = [pytest.mark.phase3, pytest.mark.integration]

_MANIFEST = ["graph_none", "trace_fs_v1", "valkey_v1", "vector_none"]
_OWNER = "e3-live"
_IMAGE = "tensorchord/vchord-suite@sha256:c6e5e77a1180199f91b040b6e85c6d10b0ded6d49fb614dfd2e7272ffb91af08"
_DOCKER = shutil.which("docker")


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    if _DOCKER is None:
        raise RuntimeError("Docker is unavailable for isolated E3 Postgres")
    return subprocess.run(  # noqa: S603 - fixed Docker executable/test-owned arguments
        [_DOCKER, *args], check=check, text=True, capture_output=True
    )


@pytest.fixture
def dedicated_0011_dsn() -> Iterator[str]:
    """Fresh disposable pinned PG18, shared gate name with the c12 suite."""

    if os.environ.get("TB_0011_DOCKER_LIVE") != "1":
        pytest.skip("set TB_0011_DOCKER_LIVE=1 for isolated E3 PostgreSQL")
    if _DOCKER is None:
        pytest.skip("Docker is unavailable for isolated E3 PostgreSQL")
    if _docker("image", "inspect", _IMAGE, check=False).returncode != 0:
        pytest.skip("pinned PG18 image is not available locally")
    name = f"tracebed-e3-live-{uuid4().hex}"
    _docker(
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-e",
        "POSTGRES_USER=tracebed_owner",
        "-e",
        f"POSTGRES_PASSWORD={_OWNER_PASSWORD}",
        "-e",
        "POSTGRES_DB=tracebed",
        "-p",
        "127.0.0.1::5432",
        _IMAGE,
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
            pytest.fail("isolated E3 PostgreSQL did not become ready")
        port = _docker("port", name, "5432/tcp").stdout.strip().rsplit(":", 1)[-1]
        assert port.isdecimal()
        dsn = f"postgresql://tracebed_owner:{_OWNER_PASSWORD}@127.0.0.1:{port}/tracebed"
        for _ in range(20):
            try:
                with psycopg.connect(dsn, connect_timeout=1):
                    pass
            except psycopg.OperationalError:
                time.sleep(0.25)
            else:
                break
        else:
            pytest.fail("isolated E3 PostgreSQL is not reachable")
        yield dsn
    finally:
        _docker("rm", "-f", name, check=False)


@contextmanager
def _temporary_erasure_dsn(owner_dsn: str) -> Iterator[str]:
    """Create the one test-only LOGIN shape accepted by the E3 caller guard."""

    role = f"e3_live_{uuid4().hex}"
    password = f"e3-live-{uuid4().hex}"
    role_ident = sql.Identifier(role)
    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD {}"
            ).format(role_ident, sql.Literal(password))
        )
        owner.execute(
            sql.SQL(
                "GRANT tracebed_erasure_group TO {} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            ).format(role_ident)
        )
        owner.execute(sql.SQL("GRANT CONNECT ON DATABASE tracebed TO {}").format(role_ident))
        owner.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role_ident))
    try:
        yield owner_dsn.replace("tracebed_owner", role).replace(_OWNER_PASSWORD, password)
    finally:
        with psycopg.connect(owner_dsn, autocommit=True) as owner:
            owner.execute(sql.SQL("REVOKE USAGE ON SCHEMA public FROM {}").format(role_ident))
            owner.execute(sql.SQL("REVOKE CONNECT ON DATABASE tracebed FROM {}").format(role_ident))
            owner.execute(sql.SQL("REVOKE tracebed_erasure_group FROM {}").format(role_ident))
            owner.execute(sql.SQL("DROP ROLE {}").format(role_ident))


def _activate_c12_with_project(owner_dsn: str) -> tuple[UUID, UUID, UUID, UUID]:
    """Stage c11, use its explicit c12 action, and return project actor/grant."""

    _apply_through_0010(owner_dsn)
    _harden_legacy_role_for_cutover(owner_dsn)
    with psycopg.connect(owner_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        identity = owner.execute(
            "SELECT registration.principal_id, registration.agent_type_id "
            "FROM public.agent_registration AS registration "
            "WHERE registration.project_id = %s",
            (project_id,),
        ).fetchone()
        assert identity is not None
        owner.commit()
    assert apply_migrations(_attested_dsn(owner_dsn), through="0011_authority_cutover") == [
        "0011_authority_cutover"
    ]
    bootstrap.bootstrap_database(
        owner_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    bootstrap.bootstrap_database(
        owner_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="cutover-0012",
    )
    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        grant = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'erasure_request') RETURNING grant_id",
            (identity[0], project_id),
        ).fetchone()
        assert grant is not None
    return project_id, identity[0], identity[1], grant[0]


def _activate_e4(owner_dsn: str) -> None:
    """Stage the closed c12 authority state and publish the E4 executor role."""

    _activate_c12_with_project(owner_dsn)
    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    bootstrap.bootstrap_database(
        owner_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        erasure_password="erasure-password",
        ingress_quarantined=True,
        action="cutover-0013",
    )


class _FiveSecondBudget:
    def __init__(self) -> None:
        self._end = time.monotonic() + 5.0

    def remaining_ms(self) -> float:
        return max(0.0, (self._end - time.monotonic()) * 1000.0)


def _audit_counts(owner_dsn: str, project_id: UUID, run_id: UUID) -> tuple[int, int, int]:
    with psycopg.connect(owner_dsn) as owner:
        row = owner.execute(
            "SELECT "
            "(SELECT count(*) FROM public.injection_log WHERE project_id = %s AND run_id = %s), "
            "(SELECT count(*) FROM public.retrieval_event WHERE project_id = %s AND run_id = %s), "
            "(SELECT count(*) FROM public.run_owner WHERE project_id = %s AND run_id = %s)",
            (project_id, run_id, project_id, run_id, project_id, run_id),
        ).fetchone()
    assert row is not None
    return tuple(int(value) for value in row)  # type: ignore[return-value]


def test_live_e4_api_role_retrieval_audit_is_atomic(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The API role commits run ownership and both terminal audit writes together."""

    _activate_e4(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        identity = owner.execute(
            "SELECT principal_id, agent_type_id, project_id FROM public.agent_registration LIMIT 1"
        ).fetchone()
        assert identity is not None
        principal_id, agent_type_id, project_id = identity
        grant = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'data') RETURNING grant_id",
            (principal_id, project_id),
        ).fetchone()
        assert grant is not None
        memory_id = uuid4()
        owner.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        owner.execute(
            "INSERT INTO public.memory_item ("
            "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
            "content, content_hash, token_count, provenance, scan_verdict_id, subject_digests"
            ") VALUES (%s, %s, 'agent_type', %s, 'lesson', 'audit_live', 'operational', 'A', "
            "'validated', 'atomic audit sentinel', %s, 3, "
            "jsonb_build_object('class', 'operator', 'principal', %s::text), %s, "
            "ARRAY[public.tracebed_subject_digest(%s, '__project__')]::bytea[])",
            (
                memory_id,
                project_id,
                agent_type_id,
                "a" * 64,
                str(principal_id),
                uuid4(),
                project_id,
            ),
        )
        owner.execute("SELECT public.tracebed_open_authority_admission()")
        owner.commit()

    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    api_pool = ConnectionPool(api_dsn, min_size=1, max_size=1, open=True)
    activity_pool = create_activity_pool(
        api_dsn, connect_timeout_s=2, checkout_timeout_s=2.0, min_size=1, max_size=1
    )
    try:
        repo = Repo(api_pool, FakeClock())
        opener = AuthorizedRetrievalOpener(
            api_pool, activity=ActivityGate(activity_pool), audit_repo=repo
        )
        access = AccessContext(
            project_id=ProjectId(project_id),
            agent_type_id=AgentTypeId(agent_type_id),
            principal_id=PrincipalId(principal_id),
            grants=(GrantBinding(grant[0], ProjectRole.DATA),),
        )
        budget = _FiveSecondBudget()
        run_id = RunId(uuid4())
        row = RetrievalEventInsert(
            run_id=run_id,
            outcome_code=OutcomeCode.INJECTED,
            latency_ms=1,
            embed_latency_ms=None,
            candidates_considered=1,
            top_score=0.1,
            arm=Arm.MEMORY_ON,
        )
        injection = InjectionRow(MemoryId(memory_id), Slot.JIT_LESSON, 0.1, 1)
        with opener.hold(access, run_id, deadline=budget) as scope:
            assert scope.audit is not None
            scope.audit.record_terminal(injections=(injection,), row=row)
            assert _audit_counts(dedicated_0011_dsn, project_id, run_id.value) == (0, 0, 0)
        assert _audit_counts(dedicated_0011_dsn, project_id, run_id.value) == (1, 1, 1)

        failed_run = RunId(uuid4())
        original = repo._impl_insert_retrieval_event
        terminal_failure = RuntimeError("second audit write failed")

        def fail_terminal(conn: psycopg.Connection[Any], *args: object, **kwargs: object) -> None:
            assert conn.execute(
                "SELECT count(*) FROM public.injection_log WHERE project_id = %s AND run_id = %s",
                (project_id, failed_run.value),
            ).fetchone() == (1,)
            raise terminal_failure

        monkeypatch.setattr(repo, "_impl_insert_retrieval_event", fail_terminal)
        with (
            pytest.raises(RetrievalAuditUnavailable) as raised,
            opener.hold(access, failed_run, deadline=_FiveSecondBudget()) as scope,
        ):
            assert scope.audit is not None
            scope.audit.record_terminal(
                injections=(injection,),
                row=RetrievalEventInsert(
                    run_id=failed_run,
                    outcome_code=row.outcome_code,
                    latency_ms=1,
                    embed_latency_ms=None,
                    candidates_considered=1,
                    top_score=0.1,
                    arm=Arm.MEMORY_ON,
                ),
            )
        assert raised.value.__cause__ is terminal_failure
        assert _audit_counts(dedicated_0011_dsn, project_id, failed_run.value) == (0, 0, 0)
        monkeypatch.setattr(repo, "_impl_insert_retrieval_event", original)
    finally:
        activity_pool.close()
        api_pool.close()


def _catalog_tombstone(owner_dsn: str) -> tuple[UUID, str]:
    """Build the one catalog shape c12 may normalize after real E3 completion.

    The end-to-end E3 test below proves the receipt/saga path.  This narrow
    fixture starts from real c12 provisioning and makes the same retained
    leaf shape so each near-miss catalog mutation can be rolled back and
    checked independently without weakening production lifecycle guards.
    """

    project_id, _principal_id, _agent_type_id, _grant_id = _activate_c12_with_project(owner_dsn)
    subject_key_leaf = partition_name("subject_key", ProjectId(project_id))
    with psycopg.connect(owner_dsn) as owner:
        owner.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        digest = owner.execute(
            "SELECT public.tracebed_subject_digest(%s, 'catalog-tombstone-key')", (project_id,)
        ).fetchone()
        assert digest is not None and isinstance(digest[0], bytes)
        owner.execute(
            "INSERT INTO public.subject_key ("
            "project_id, subject_tag, subject_digest, wrap_version, key_id, wrapped_kek"
            ") VALUES (%s, 'catalog-tombstone-key', %s, 1, %s, %s)",
            (project_id, digest[0], uuid4(), b"k" * 60),
        )
        for parent in PARTITIONED_TABLES:
            if parent == "subject_key":
                continue
            leaf = partition_name(parent, ProjectId(project_id))
            owner.execute(
                sql.SQL("ALTER TABLE public.{} DETACH PARTITION public.{}").format(
                    sql.Identifier(parent), sql.Identifier(leaf)
                )
            )
            owner.execute(sql.SQL("DROP TABLE public.{}").format(sql.Identifier(leaf)))
        owner.execute(
            "UPDATE public.project SET status = 'deleting' WHERE project_id = %s", (project_id,)
        )
        owner.execute("ALTER TABLE public.project DISABLE TRIGGER USER")
        owner.execute(
            "UPDATE public.project SET status = 'deleted', deleted_at = clock_timestamp(), "
            "name = 'deleted-project', retention_policy = NULL, provisioning_key_hash = NULL, "
            "provisioning_request_hash = NULL WHERE project_id = %s",
            (project_id,),
        )
        owner.execute("ALTER TABLE public.project ENABLE TRIGGER USER")
        owner.execute(
            sql.SQL("ALTER TABLE public.{} DISABLE TRIGGER USER").format(
                sql.Identifier(subject_key_leaf)
            )
        )
        owner.execute(
            sql.SQL(
                "UPDATE public.{} SET destroyed_at = clock_timestamp(), wrapped_kek = ''::bytea, "
                "subject_tag = NULL WHERE project_id = %s"
            ).format(sql.Identifier(subject_key_leaf)),
            (project_id,),
        )
        owner.execute(
            sql.SQL("ALTER TABLE public.{} ENABLE TRIGGER USER").format(
                sql.Identifier(subject_key_leaf)
            )
        )
        owner.commit()
    return project_id, subject_key_leaf


def _assert_c12_catalog_tombstone_drift(
    owner: psycopg.Connection[Any], mutation: Callable[[], None]
) -> None:
    """Require one mutation to be visible, then roll it back exactly."""

    owner.execute("SAVEPOINT catalog_tombstone_drift")
    try:
        mutation()
        with pytest.raises(psycopg.Error, match="authority profile drift"):
            owner.execute(
                "SELECT public.authority_acl_security_assert('cutover_0012'), "
                "public.authority_schema_security_assert('cutover_0012')"
            )
    finally:
        owner.execute("ROLLBACK TO SAVEPOINT catalog_tombstone_drift")
        owner.execute("RELEASE SAVEPOINT catalog_tombstone_drift")


def test_live_e4_deployment_receipt_is_invariant_across_session_timezones(
    dedicated_0011_dsn: str,
) -> None:
    """PG18 must authenticate one E4 epoch identically in every TimeZone."""

    _activate_c12_with_project(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        erasure_password="erasure-password",
        ingress_quarantined=True,
        action="cutover-0013",
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("SET TIME ZONE 'UTC'")
        utc = owner.execute(
            "SELECT receipt_digest, public.erasure_deployment_security_assert() "
            "FROM public.erasure_deployment_epoch"
        ).fetchone()
        owner.execute("SET TIME ZONE 'Pacific/Auckland'")
        pacific = owner.execute(
            "SELECT receipt_digest, public.erasure_deployment_security_assert() "
            "FROM public.erasure_deployment_epoch"
        ).fetchone()
    assert utc is not None and pacific is not None and utc == pacific


def test_live_e4_receipt_survives_normal_post_deployment_project_provisioning(
    dedicated_0011_dsn: str,
) -> None:
    """A new canonical project partition must not look like ACL/profile drift."""

    _activate_c12_with_project(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        erasure_password="erasure-password",
        ingress_quarantined=True,
        action="cutover-0013",
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
        assert (
            owner.execute("SELECT public.erasure_deployment_security_assert()").fetchone()
            is not None
        )


def test_live_e4_readiness_prelocks_parents_before_provisioning_can_lock_successors(
    dedicated_0011_dsn: str,
) -> None:
    """A blocked readiness reader never holds a later parent lock first."""

    _activate_e4(dedicated_0011_dsn)
    erasure_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_erasure", "erasure-password")
    backend_pids: Queue[int] = Queue()
    errors: Queue[BaseException] = Queue()

    def readiness() -> None:
        try:
            with psycopg.connect(erasure_dsn) as erasure:
                row = erasure.execute("SELECT pg_backend_pid()").fetchone()
                assert row is not None and isinstance(row[0], int)
                backend_pids.put(row[0])
                erasure.execute("SELECT public.tracebed_erasure_prepublication_readiness()")
                erasure.commit()
        except BaseException as error:  # pragma: no cover - reported in the parent thread
            errors.put(error)

    worker = Thread(target=readiness, daemon=True)
    try:
        with psycopg.connect(dedicated_0011_dsn) as provisioner:
            provisioner.execute("LOCK TABLE ONLY public.memory_item IN ACCESS EXCLUSIVE MODE")
            worker.start()
            try:
                try:
                    backend_pid = backend_pids.get(timeout=5)
                except Empty:
                    if not errors.empty():
                        error = errors.get()
                        raise error from None
                    pytest.fail("erasure readiness did not establish its authenticated session")

                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    waiting = provisioner.execute(
                        "SELECT wait_event_type = 'Lock' AND wait_event = 'relation' "
                        "FROM pg_stat_activity WHERE pid = %s",
                        (backend_pid,),
                    ).fetchone()
                    if waiting == (True,):
                        break
                    if not errors.empty():
                        raise errors.get()
                    time.sleep(0.02)
                else:
                    pytest.fail("erasure readiness did not wait on the first parent lock")

                assert provisioner.execute(
                    "SELECT count(*) FROM pg_locks "
                    "WHERE pid = %s AND relation = 'public.subject_key'::regclass",
                    (backend_pid,),
                ).fetchone() == (0,)
                provisioner.execute(
                    "LOCK TABLE ONLY public.subject_key IN ACCESS EXCLUSIVE MODE NOWAIT"
                )
            finally:
                provisioner.rollback()
    finally:
        if worker.ident is not None:
            worker.join(timeout=10)

    assert not worker.is_alive()
    if not errors.empty():
        raise errors.get()


def test_live_e4_readiness_and_real_project_provisioning_remain_deadlock_free(
    dedicated_0011_dsn: str,
) -> None:
    """Exercise actual E4 readiness alongside repeated post-deployment DDL."""

    _activate_e4(dedicated_0011_dsn)
    erasure_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_erasure", "erasure-password")
    stop = Event()
    first_ready = Event()
    errors: Queue[BaseException] = Queue()
    ready_count = [0]

    def readiness_loop() -> None:
        try:
            with psycopg.connect(erasure_dsn) as erasure:
                while not stop.is_set():
                    erasure.execute("SELECT public.tracebed_erasure_prepublication_readiness()")
                    erasure.commit()
                    ready_count[0] += 1
                    first_ready.set()
        except BaseException as error:  # pragma: no cover - reported in the parent thread
            errors.put(error)
            first_ready.set()

    worker = Thread(target=readiness_loop, daemon=True)
    worker.start()
    try:
        assert first_ready.wait(timeout=5)
        if not errors.empty():
            raise errors.get()
        with psycopg.connect(dedicated_0011_dsn) as provisioner:
            for _ in range(4):
                project_id = uuid4()
                provisioner.execute(
                    "INSERT INTO public.project (project_id, name, status) VALUES (%s, %s, 'active')",
                    (project_id, f"e4-lock-order-{project_id.hex}"),
                )
                create_project_partitions(provisioner, ProjectId(project_id))
                provisioner.commit()
                if not errors.empty():
                    raise errors.get()
    finally:
        stop.set()
        worker.join(timeout=10)

    assert not worker.is_alive()
    if not errors.empty():
        raise errors.get()
    assert ready_count[0] >= 2


def test_live_e4_preactivity_rollback_and_reapply_preserve_the_closed_chain(
    dedicated_0011_dsn: str,
) -> None:
    """Exercise the supported c10→c13 rollback/reapply boundary before activity."""

    _activate_e4(dedicated_0011_dsn)
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="rollback-0013",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0012_erasure_saga"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tracebed_erasure'), "
            "public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True, True)

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        erasure_password="erasure-password",
        ingress_quarantined=True,
        action="cutover-0013",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0013_erasure_deployment"
    erasure_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_erasure", "erasure-password")
    with psycopg.connect(erasure_dsn) as erasure:
        assert (
            erasure.execute("SELECT public.tracebed_erasure_prepublication_readiness()").fetchone()
            is not None
        )


def test_live_c12_tombstone_normalization_rejects_every_near_miss(
    dedicated_0011_dsn: str,
) -> None:
    """Only one fully scrubbed canonical subject-key leaf may be normalized."""

    project_id, subject_key_leaf = _catalog_tombstone(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True)

        policy = owner.execute(
            "SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = %s "
            "ORDER BY policyname LIMIT 1",
            (subject_key_leaf,),
        ).fetchone()
        index = owner.execute(
            "SELECT index_class.relname FROM pg_index AS index_data "
            "JOIN pg_class AS index_class ON index_class.oid = index_data.indexrelid "
            "WHERE index_data.indrelid = %s::regclass AND NOT index_data.indisprimary "
            "ORDER BY index_class.relname LIMIT 1",
            (f"public.{subject_key_leaf}",),
        ).fetchone()
        trigger = owner.execute(
            "SELECT tgname FROM pg_trigger WHERE tgrelid = %s::regclass AND NOT tgisinternal "
            "ORDER BY tgname LIMIT 1",
            (f"public.{subject_key_leaf}",),
        ).fetchone()
        assert policy is not None and isinstance(policy[0], str)
        assert index is not None and isinstance(index[0], str)
        assert trigger is not None and isinstance(trigger[0], str)

        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("ALTER TABLE public.{} NO FORCE ROW LEVEL SECURITY").format(
                    sql.Identifier(subject_key_leaf)
                )
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("DROP POLICY {} ON public.{}").format(
                    sql.Identifier(policy[0]), sql.Identifier(subject_key_leaf)
                )
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("ALTER INDEX public.{} SET (fillfactor = 70)").format(
                    sql.Identifier(index[0])
                )
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("ALTER TABLE public.{} DISABLE TRIGGER {}").format(
                    sql.Identifier(subject_key_leaf), sql.Identifier(trigger[0])
                )
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("GRANT INSERT ON TABLE public.{} TO tracebed_api_group").format(
                    sql.Identifier(subject_key_leaf)
                )
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("GRANT SELECT (key_id) ON TABLE public.{} TO tracebed_api_group").format(
                    sql.Identifier(subject_key_leaf)
                )
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL(
                    "GRANT SELECT ON TABLE public.{} TO tracebed_worker_group WITH GRANT OPTION"
                ).format(sql.Identifier(subject_key_leaf))
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("ALTER TABLE public.subject_key DETACH PARTITION public.{}").format(
                    sql.Identifier(subject_key_leaf)
                )
            ),
        )
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL("ALTER TABLE public.{} RENAME TO tombstone_subject_key_renamed").format(
                    sql.Identifier(subject_key_leaf)
                )
            ),
        )
        shadow_schema = f"tombstone_shadow_{project_id.hex[:12]}"

        def moved_homonym() -> None:
            owner.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(shadow_schema)))
            owner.execute(
                sql.SQL("ALTER TABLE public.{} SET SCHEMA {}").format(
                    sql.Identifier(subject_key_leaf), sql.Identifier(shadow_schema)
                )
            )

        _assert_c12_catalog_tombstone_drift(owner, moved_homonym)

        extra_leaf = f"memory_item_tombstone_extra_{project_id.hex[:12]}"
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL(
                    "CREATE TABLE public.{} PARTITION OF public.memory_item FOR VALUES IN ({})"
                ).format(sql.Identifier(extra_leaf), sql.Literal(project_id))
            ),
        )
        wrong_bound_leaf = f"subject_key_tombstone_wrong_bound_{project_id.hex[:12]}"
        _assert_c12_catalog_tombstone_drift(
            owner,
            lambda: owner.execute(
                sql.SQL(
                    "CREATE TABLE public.{} PARTITION OF public.subject_key FOR VALUES IN ({})"
                ).format(sql.Identifier(wrong_bound_leaf), sql.Literal(uuid4()))
            ),
        )

        def unsanitized_project() -> None:
            owner.execute("ALTER TABLE public.project DISABLE TRIGGER USER")
            owner.execute(
                "UPDATE public.project SET retention_policy = '{\"retained\": true}'::jsonb "
                "WHERE project_id = %s",
                (project_id,),
            )
            owner.execute("ALTER TABLE public.project ENABLE TRIGGER USER")

        def nonfinite_tombstone() -> None:
            owner.execute("ALTER TABLE public.project DISABLE TRIGGER USER")
            owner.execute(
                "UPDATE public.project SET deleted_at = 'infinity'::timestamptz WHERE project_id = %s",
                (project_id,),
            )
            owner.execute("ALTER TABLE public.project ENABLE TRIGGER USER")

        def deleting_project() -> None:
            owner.execute("ALTER TABLE public.project DISABLE TRIGGER USER")
            owner.execute(
                "UPDATE public.project SET status = 'deleting', deleted_at = NULL WHERE project_id = %s",
                (project_id,),
            )
            owner.execute("ALTER TABLE public.project ENABLE TRIGGER USER")

        def live_key() -> None:
            owner.execute(
                sql.SQL("ALTER TABLE public.{} DISABLE TRIGGER USER").format(
                    sql.Identifier(subject_key_leaf)
                )
            )
            owner.execute(
                sql.SQL(
                    "UPDATE public.{} SET destroyed_at = NULL, wrapped_kek = %s, wrap_version = 2, "
                    "subject_tag = NULL WHERE project_id = %s"
                ).format(sql.Identifier(subject_key_leaf)),
                (b"l" * 60, project_id),
            )
            owner.execute(
                sql.SQL("ALTER TABLE public.{} ENABLE TRIGGER USER").format(
                    sql.Identifier(subject_key_leaf)
                )
            )

        def malformed_key() -> None:
            digest = owner.execute(
                "SELECT public.tracebed_subject_digest(%s, 'e3-project-key')", (project_id,)
            ).fetchone()
            assert digest is not None and isinstance(digest[0], bytes)
            owner.execute(
                sql.SQL("ALTER TABLE public.{} DISABLE TRIGGER USER").format(
                    sql.Identifier(subject_key_leaf)
                )
            )
            owner.execute(
                sql.SQL(
                    "UPDATE public.{} SET subject_tag = 'e3-project-key', subject_digest = %s "
                    "WHERE project_id = %s"
                ).format(sql.Identifier(subject_key_leaf)),
                (digest[0], project_id),
            )
            owner.execute(
                sql.SQL("ALTER TABLE public.{} ENABLE TRIGGER USER").format(
                    sql.Identifier(subject_key_leaf)
                )
            )

        _assert_c12_catalog_tombstone_drift(owner, unsanitized_project)
        _assert_c12_catalog_tombstone_drift(owner, nonfinite_tombstone)
        _assert_c12_catalog_tombstone_drift(owner, deleting_project)
        _assert_c12_catalog_tombstone_drift(owner, live_key)
        _assert_c12_catalog_tombstone_drift(owner, malformed_key)

        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True)


def test_live_e4_receipt_rejects_direct_or_effective_privilege_drift(
    dedicated_0011_dsn: str,
) -> None:
    """A later raw grant must invalidate E4 before readiness can bless it."""

    _activate_c12_with_project(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        erasure_password="erasure-password",
        ingress_quarantined=True,
        action="cutover-0013",
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        assert (
            owner.execute("SELECT public.erasure_deployment_security_assert()").fetchone()
            is not None
        )
        owner.execute("GRANT SELECT ON TABLE public.project TO tracebed_erasure")
        assert owner.execute(
            "SELECT has_table_privilege('tracebed_erasure', 'public.project', 'SELECT')"
        ).fetchone() == (True,)
        with pytest.raises(psycopg.Error, match="erasure deployment manifest drift"):
            owner.execute("SELECT public.erasure_deployment_security_assert()")


def _claim(
    conn: psycopg.Connection[Any],
    project_id: UUID,
    request_id: UUID,
    *,
    expected_phase: str = "fenced",
) -> tuple[int, UUID]:
    row = conn.execute(
        "SELECT project_id, request_id, scope, phase, generation, lease_token "
        "FROM public.tracebed_erasure_claim_request(%s, %s, 90, %s::text[])",
        (request_id, _OWNER, _MANIFEST),
    ).fetchone()
    assert row is not None
    assert row[:4] == (project_id, request_id, "project", expected_phase)
    assert type(row[4]) is int and type(row[5]) is UUID
    return row[4], row[5]


def _advance_through_external_checkpoints(
    conn: psycopg.Connection[Any],
    project_id: UUID,
    request_id: UUID,
    generation: int,
    token: UUID,
) -> None:
    """Use only public E3 routines to create real current-revision proofs."""

    conn.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
    crypto = conn.execute(
        "SELECT phase, closure_revision FROM public.tracebed_erasure_crypto_step(%s, %s, %s, %s, %s)",
        (project_id, request_id, generation, token, _OWNER),
    ).fetchone()
    assert crypto is not None and crypto[0] == "crypto_erased"
    revision = crypto[1]
    assert type(revision) is int
    empty_trace_manifest = hashlib.sha256(b"tracebed.erasure-trace-manifest/v1\x00").digest()
    conn.execute(
        "SELECT public.tracebed_erasure_seal_trace_manifest(%s, %s, %s, %s, %s, %s, 0, %s)",
        (project_id, request_id, generation, token, _OWNER, revision, empty_trace_manifest),
    )
    prepared = conn.execute(
        "SELECT closure_revision, pending_external "
        "FROM public.tracebed_erasure_prepare_primary(%s, %s, %s, %s, %s)",
        (project_id, request_id, generation, token, _OWNER),
    ).fetchone()
    assert prepared is not None and prepared[0] == revision
    primary = conn.execute(
        "SELECT batch_code, remaining FROM public.tracebed_erasure_primary_batch(%s, %s, %s, %s, %s, 100)",
        (project_id, request_id, generation, token, _OWNER),
    ).fetchone()
    assert primary is not None and primary == ("postgres", 0)

    for code in _MANIFEST:
        works = conn.execute(
            "SELECT work_id, work_revision FROM public.tracebed_erasure_external_work_batch("
            "%s, %s, %s, %s, %s, %s, 100)",
            (project_id, request_id, generation, token, _OWNER, code),
        ).fetchall()
        for work_id, work_revision in works:
            conn.execute(
                "SELECT public.tracebed_erasure_mark_external_work("
                "%s, %s, %s, %s, %s, %s, %s, 0, %s, 'already_absent')",
                (
                    project_id,
                    request_id,
                    generation,
                    token,
                    _OWNER,
                    work_id,
                    work_revision,
                    b"\x11" * 32,
                ),
            )
        closed = conn.execute(
            "SELECT phase, closure_revision FROM public.tracebed_erasure_close_external_step("
            "%s, %s, %s, %s, %s, %s, %s, 0, %s, 'already_absent')",
            (
                project_id,
                request_id,
                generation,
                token,
                _OWNER,
                code,
                len(works),
                hashlib.sha256(b"e3-live-close/v1:" + code.encode()).digest(),
            ),
        ).fetchone()
        assert closed is not None and closed[1] == revision
    conn.commit()


def test_live_e3_receipt_chain_checkpoint_recovery_and_project_key_tombstone(
    dedicated_0011_dsn: str,
) -> None:
    """Exercise fenced receipt, lease, recovery close, purge, tombstone, status."""

    project_id, principal_id, agent_type_id, grant_id = _activate_c12_with_project(
        dedicated_0011_dsn
    )
    key_id = uuid4()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        key_digest = owner.execute(
            "SELECT public.tracebed_subject_digest(%s, 'e3-project-key')", (project_id,)
        ).fetchone()
        assert key_digest is not None
        owner.execute(
            "INSERT INTO public.subject_key ("
            "project_id, subject_tag, subject_digest, wrap_version, key_id, wrapped_kek"
            ") VALUES (%s, 'e3-project-key', %s, 1, %s, %s)",
            (project_id, key_digest[0], key_id, b"k" * 60),
        )
        owner.commit()

    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    with psycopg.connect(api_dsn) as api:
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        requested = api.execute(
            "SELECT request_id, phase, disposition FROM public.tracebed_request_erasure("
            "%s, %s, %s, %s, 'project', NULL)",
            (project_id, principal_id, agent_type_id, grant_id),
        ).fetchone()
        assert requested is not None and requested[1:] == ("fenced", "active")
        request_id = requested[0]
        assert type(request_id) is UUID
        api.commit()

    with psycopg.connect(dedicated_0011_dsn) as owner:
        fence = owner.execute(
            "SELECT step_seq, generation, previous_receipt_digest, receipt_digest, "
            "receipt_digest = public.tracebed_erasure_receipt_digest("
            "project_id, request_id, step_seq, generation, step_code, result, result_code, attempt, "
            "affected_rows, work_revision, postcondition_digest, previous_receipt_digest, started_at, finished_at) "
            "FROM public.erasure_step_receipt WHERE request_id = %s ORDER BY step_seq",
            (request_id,),
        ).fetchall()
        assert len(fence) == 1
        assert fence[0][0:3] == (1, 0, None)
        assert type(fence[0][3]) is bytes and len(fence[0][3]) == 32 and fence[0][4] is True

    with _temporary_erasure_dsn(dedicated_0011_dsn) as erasure_dsn:
        with psycopg.connect(erasure_dsn) as worker:
            generation, token = _claim(worker, project_id, request_id)
            worker.execute(
                "SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),)
            )
            worker.execute(
                "SELECT public.tracebed_erasure_fail("
                "%s, %s, %s, %s, %s, 'crypto', 'blocked', 'configuration_mismatch', 0, %s)",
                (project_id, request_id, generation, token, _OWNER, b"\x22" * 32),
            )
            worker.commit()

        # Resume is a global fixed-code operator action.  It must write its
        # own chained receipt and cursor update atomically; it is not a raw
        # owner transition that silently reactivates the request.
        with psycopg.connect(erasure_dsn) as resumer:
            resumer.execute(
                "SELECT public.tracebed_erasure_resume_blocked(%s, 'operator_resumed')",
                (request_id,),
            )
            resumer.commit()

        with psycopg.connect(dedicated_0011_dsn) as owner:
            resumed = owner.execute(
                "SELECT step_seq, step_code, result, result_code, previous_receipt_digest, receipt_digest "
                "FROM public.erasure_step_receipt WHERE request_id = %s ORDER BY step_seq",
                (request_id,),
            ).fetchall()
            assert [row[1:4] for row in resumed] == [
                ("fence", "succeeded", "ok"),
                ("crypto", "blocked", "configuration_mismatch"),
                ("queue", "succeeded", "operator_resumed"),
            ]
            assert resumed[2][0] == 3 and resumed[2][4] == resumed[1][5]
            assert owner.execute(
                "SELECT disposition, next_step_seq, last_receipt_digest "
                "FROM public.erasure_request WHERE request_id = %s",
                (request_id,),
            ).fetchone() == ("active", 4, resumed[2][5])
            assert owner.execute(
                "SELECT count(*) FROM public.erasure_execution_capability WHERE request_id = %s",
                (request_id,),
            ).fetchone() == (0,)

        with psycopg.connect(erasure_dsn) as worker:
            generation, token = _claim(worker, project_id, request_id)
            assert generation == 2
            first_generation = generation
            _advance_through_external_checkpoints(worker, project_id, request_id, generation, token)
            phase = worker.execute(
                "SELECT phase FROM public.tracebed_erasure_inspect(%s)", (request_id,)
            ).fetchone()
            assert phase == ("external_purged",)
            worker.execute(
                "SELECT public.tracebed_erasure_release(%s, %s, %s, %s, %s)",
                (project_id, request_id, generation, token, _OWNER),
            )
            worker.commit()

        with psycopg.connect(dedicated_0011_dsn) as owner:
            receipt_count = owner.execute(
                "SELECT count(*) FROM public.erasure_step_receipt WHERE request_id = %s",
                (request_id,),
            ).fetchone()
            assert receipt_count is not None
            checkpoints = owner.execute(
                "SELECT store_code, postcondition_digest FROM public.erasure_store_checkpoint "
                "WHERE request_id = %s ORDER BY store_code",
                (request_id,),
            ).fetchall()
            assert len(checkpoints) == len(_MANIFEST)

        # New connection/generation models a process crash after every close
        # checkpoint committed but before final verify.  Deliberately supply a
        # different aggregate digest: current verified checkpoints are the
        # authority and the no-op close must not add a conflicting receipt.
        with psycopg.connect(erasure_dsn) as successor:
            successor.execute(
                "SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),)
            )
            generation, token = _claim(
                successor, project_id, request_id, expected_phase="external_purged"
            )
            assert generation == first_generation + 1
            for code in _MANIFEST:
                replayed = successor.execute(
                    "SELECT phase FROM public.tracebed_erasure_close_external_step("
                    "%s, %s, %s, %s, %s, %s, 0, 0, %s, 'already_absent')",
                    (project_id, request_id, generation, token, _OWNER, code, b"\xfe" * 32),
                ).fetchone()
                assert replayed == ("external_purged",)
            completed = successor.execute(
                "SELECT completed, phase FROM public.tracebed_erasure_verify_and_complete("
                "%s, %s, %s, %s, %s)",
                (project_id, request_id, generation, token, _OWNER),
            ).fetchone()
            assert completed == (True, "scope_complete")
            successor.commit()

    with psycopg.connect(dedicated_0011_dsn) as owner:
        after = owner.execute(
            "SELECT count(*) FROM public.erasure_step_receipt WHERE request_id = %s", (request_id,)
        ).fetchone()
        assert after == (receipt_count[0] + 2,)
        assert (
            owner.execute(
                "SELECT store_code, postcondition_digest FROM public.erasure_store_checkpoint "
                "WHERE request_id = %s ORDER BY store_code",
                (request_id,),
            ).fetchall()
            == checkpoints
        )
        chain = owner.execute(
            "SELECT step_seq, previous_receipt_digest, receipt_digest, "
            "receipt_digest = public.tracebed_erasure_receipt_digest("
            "project_id, request_id, step_seq, generation, step_code, result, result_code, attempt, "
            "affected_rows, work_revision, postcondition_digest, previous_receipt_digest, started_at, finished_at) "
            "FROM public.erasure_step_receipt WHERE request_id = %s ORDER BY step_seq",
            (request_id,),
        ).fetchall()
        previous: bytes | None = None
        for expected_sequence, (sequence, prior, digest, recomputed) in enumerate(chain, start=1):
            assert sequence == expected_sequence and prior == previous and recomputed is True
            assert type(digest) is bytes and len(digest) == 32
            previous = digest
        assert owner.execute(
            "SELECT final_receipt_digest FROM public.erasure_request WHERE request_id = %s",
            (request_id,),
        ).fetchone() == (previous,)
        assert owner.execute(
            "SELECT status, deleted_at IS NOT NULL, name FROM public.project WHERE project_id = %s",
            (project_id,),
        ).fetchone() == ("deleted", True, "deleted-project")
        remaining_partitions = tuple(
            table
            for table in PARTITIONED_TABLES
            if owner.execute(
                "SELECT to_regclass(%s) IS NOT NULL",
                (f"public.{partition_name(table, ProjectId(project_id))}",),
            ).fetchone()
            == (True,)
        )
        assert remaining_partitions == ("subject_key",)
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True)
        key = owner.execute(
            "SELECT destroyed_at IS NOT NULL, wrapped_kek = ''::bytea, subject_tag IS NULL "
            "FROM public.subject_key WHERE project_id = %s AND key_id = %s",
            (project_id, key_id),
        ).fetchone()
        assert key == (True, True, True)
        assert owner.execute(
            "SELECT to_regclass(%s) IS NOT NULL",
            (f"public.{partition_name('subject_key', ProjectId(project_id))}",),
        ).fetchone() == (True,)

    with psycopg.connect(api_dsn) as api:
        status = api.execute(
            "SELECT request_id, phase, disposition FROM public.tracebed_erasure_request_status_by_actor("
            "%s, %s)",
            (principal_id, request_id),
        ).fetchone()
        assert status == (request_id, "scope_complete", "scope_complete")


def test_live_p0014_maps_to_a_retryable_closure_changed_receipt(
    dedicated_0011_dsn: str,
) -> None:
    """A real c12 P0014 is an automatic retry signal, never an operator block."""

    project_id, principal_id, agent_type_id, grant_id = _activate_c12_with_project(
        dedicated_0011_dsn
    )
    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    with psycopg.connect(api_dsn) as api:
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        requested = api.execute(
            "SELECT request_id FROM public.tracebed_request_erasure("
            "%s, %s, %s, %s, 'project', NULL)",
            (project_id, principal_id, agent_type_id, grant_id),
        ).fetchone()
        assert requested is not None and type(requested[0]) is UUID
        request_id = requested[0]
        api.commit()

    with _temporary_erasure_dsn(dedicated_0011_dsn) as erasure_dsn:
        with psycopg.connect(erasure_dsn) as worker:
            row = worker.execute(
                "SELECT project_id, request_id, scope, phase, generation, lease_token, "
                "lease_expires_at, closure_revision "
                "FROM public.tracebed_erasure_claim_request(%s, %s, 90, %s::text[])",
                (request_id, _OWNER, _MANIFEST),
            ).fetchone()
            assert row is not None
            lease = ErasureLease(*row)
            worker.commit()

        pool = ConnectionPool(erasure_dsn, min_size=1, max_size=1, open=True)
        try:
            database = PgErasureExecutorStore(pool)
            with pytest.raises(ErasureClosureChanged):
                database.verify_and_complete(lease, _OWNER)
            database.fail(lease, _OWNER, "verify", "retryable", "closure_changed")
        finally:
            pool.close()

    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT disposition, last_code, lease_token IS NULL "
            "FROM public.erasure_request WHERE request_id = %s",
            (request_id,),
        ).fetchone() == ("retry_wait", "retry_scheduled", True)
        assert owner.execute(
            "SELECT step_code, result, result_code FROM public.erasure_step_receipt "
            "WHERE request_id = %s ORDER BY step_seq DESC LIMIT 1",
            (request_id,),
        ).fetchone() == ("verify", "retryable", "closure_changed")
