"""Opt-in isolated-PG18 proofs for the 0011 dedicated-cluster cutover.

These tests intentionally never use the retained development Postgres: the
four-database inventory makes an in-cluster scratch database a fifth database
and therefore a correctly rejected topology.  Set ``TB_0011_DOCKER_LIVE=1``
to let this fixture create and remove a dedicated ephemeral container.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
from yoyo import get_backend

from tracebed.adapters.identity import Principal
from tracebed.adapters.ports import (
    AuthorizedQueueWrite,
    OutcomeQueuePayload,
    ProposalQueuePayload,
    TraceQueuePayload,
)
from tracebed.api.deps import AppDeps
from tracebed.api.main import create_app
from tracebed.core.scans import ScanContext, scan
from tracebed.crypto.subject_digest import PROJECT_SUBJECT_TAG, subject_digest, validate_subject_tag
from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EmbeddingConfig, QueueConfig, StorageConfig, TracebedSettings
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.enums import (
    FeedbackSource,
    Lane,
    MemType,
    ProjectRole,
    ProvenanceClass,
    ScopeType,
    TrustTier,
)
from tracebed.domain.errors import (
    AuthorizationDenied,
    ConfigError,
    ErasureFenced,
    RunAuthorityDenied,
)
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import Status
from tracebed.stores.pg import bootstrap
from tracebed.stores.pg import migrate as pg_migrate
from tracebed.stores.pg.activity import ActivityGate, activity_lock_key, create_activity_pool
from tracebed.stores.pg.authority import (
    AuthorityStore,
    AuthorizedInvalidationWriter,
    AuthorizedReadGate,
    AuthorizedRetrievalOpener,
)
from tracebed.stores.pg.erasure import ErasureRequestStore
from tracebed.stores.pg.lifecycle import LifecycleWriter
from tracebed.stores.pg.migrate import (
    apply_migrations,
    current_revision,
    read_all_migrations,
    rollback_migrations,
)
from tracebed.stores.pg.partitions import PARTITIONED_TABLES, ensure_schema_current, partition_name
from tracebed.stores.pg.pool import create_pool, scoped
from tracebed.stores.pg.provisioning import ProjectProvisioner
from tracebed.stores.pg.queue import (
    TOPIC_MEMORY_PROPOSAL,
    TOPIC_OUTCOME_EVENT,
    TOPIC_TRACE_EVENT,
    AuthorizedWorkQueue,
    WorkerQueue,
)
from tracebed.stores.pg.repo import ProposalCapOutcome, Repo
from tracebed.stores.pg.reports import ReportsRepo
from tracebed.stores.pg.runtime_identity import (
    assert_runtime_connection,
    probe_runtime_prepublication_readiness,
    probe_runtime_readiness,
    runtime_pool_configure,
)
from tracebed.stores.pg.search import SearchStore
from tracebed.stores.pg.trace_learning import TraceLearningJobStore
from tracebed.workers.edit_ops import MemoryStatusWrite
from tracebed.workers.trace_learning import TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION

pytestmark = [pytest.mark.phase3, pytest.mark.integration]

# Keep the clean authority reference on the exact Compose image, rather than
# accepting a moving ``pg18-latest`` catalog as a provenance baseline.
_IMAGE = "tensorchord/vchord-suite@sha256:c6e5e77a1180199f91b040b6e85c6d10b0ded6d49fb614dfd2e7272ffb91af08"
_OWNER_PASSWORD = "tracebed-0011-test-owner"
_DOCKER = shutil.which("docker")
_ROOT = Path(__file__).parents[2]


class _E1Master:
    """Fixed test-only KEK root; never a deployment credential."""

    def master_key(self) -> bytes:
        return b"e" * 32


def _independent_manifest_generator() -> object:
    """Load the release-only clean-reference generator without test coupling."""

    path = _ROOT / "scripts" / "generate_authority_acl_profile_manifest.py"
    spec = importlib.util.spec_from_file_location("authority_acl_manifest_generator_live", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _profile_rows_from_source(source: str) -> tuple[tuple[str, str, str], ...]:
    """Parse only literal source fixture values; never query a live profile table."""

    start = source.index("-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_BEGIN")
    end = source.index("-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_END")
    rows = re.findall(
        r"\('([a-z0-9_]+)'::public\.authority_acl_profile, "
        r"'([a-z]+)', decode\('([0-9a-f]{64})', 'hex'\)\)",
        source[start:end],
    )
    return tuple(rows)


def _checked_in_profile_rows() -> tuple[tuple[str, str, str], ...]:
    return _profile_rows_from_source(
        (_ROOT / "migrations" / "0010_authority_foundation.sql").read_text(encoding="utf-8")
    )


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    if _DOCKER is None:
        raise RuntimeError("Docker is unavailable for isolated authority-cutover Postgres")
    return subprocess.run(  # noqa: S603 - fixed Docker executable and test-owned arguments
        [_DOCKER, *args], check=check, text=True, capture_output=True
    )


@pytest.fixture
def dedicated_0011_dsn() -> Iterator[str]:
    """A clean dedicated cluster that is always force-removed after one test."""

    if os.environ.get("TB_0011_DOCKER_LIVE") != "1":
        pytest.skip("set TB_0011_DOCKER_LIVE=1 for isolated authority-cutover Postgres")
    if _DOCKER is None:
        pytest.skip("Docker is unavailable for isolated authority-cutover Postgres")
    image = _run("image", "inspect", _IMAGE, check=False)
    if image.returncode != 0:
        pytest.skip("PG18 authority-cutover image is not available locally")

    name = f"tracebed-0011-test-{uuid4().hex}"
    _run(
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
            ready = _run(
                "exec", name, "pg_isready", "-U", "tracebed_owner", "-d", "tracebed", check=False
            )
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            pytest.fail("isolated authority-cutover Postgres did not become ready")
        port = _run("port", name, "5432/tcp").stdout.strip().rsplit(":", 1)[-1]
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
            pytest.fail("isolated authority-cutover Postgres is not reachable from the test host")
        yield dsn
    finally:
        _run("rm", "-f", name, check=False)


def _attested_dsn(dsn: str) -> str:
    return bootstrap._dedicated_cluster_dsn(dsn, "dedicated", ingress_quarantined=True)


def _raw_yoyo_dsn(dsn: str) -> str:
    """Return an intentionally unsupported upstream-yoyo URI for guard tests."""

    assert dsn.startswith("postgresql://")
    return "postgresql+psycopg://" + dsn.removeprefix("postgresql://")


def _role_dsn(owner_dsn: str, role: str, password: str) -> str:
    return owner_dsn.replace("tracebed_owner", role).replace(_OWNER_PASSWORD, password)


def _open_authority_admission(owner_dsn: str) -> None:
    """Explicitly publish direct-test runtime authority after owner bootstrap.

    Compose performs this only after its S3/bootstrap publication sequence;
    isolated database tests invoke the same owner-only transition explicitly.
    """

    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_open_authority_admission()")


def _harden_legacy_role_for_cutover(dsn: str) -> None:
    """Model latest bootstrap's exact legacy credential state for direct yoyo."""

    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_app NOINHERIT PASSWORD 'legacy-password'")


def _quarantine_for_pre_activity_rollback(dsn: str) -> None:
    """Use the explicit owner-side receipt fence before direct yoyo rollback."""

    with psycopg.connect(_attested_dsn(dsn), autocommit=True) as owner:
        bootstrap.quarantine_authority_cutover_for_rollback(
            owner,
            owner_dsn=_attested_dsn(dsn),
            app_password="legacy-password",
            api_password="api-password",
            worker_password="worker-password",
        )


def _apply_through_0010(dsn: str) -> None:
    """Build the staged schema without bypassing 0011's required attestation."""

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(dsn)
    assert current_revision(dsn)[0] == "0010_authority_foundation"


def _apply_through_0009(dsn: str) -> None:
    """Pause a dedicated fixture at the genuine pre-authority baseline."""

    apply_migrations(dsn, through="0009_trace_index_terminal_freeze")
    assert current_revision(dsn)[0] == "0009_trace_index_terminal_freeze"


def _create_active_project_admin(conn: psycopg.Connection[Any]) -> UUID:
    """Create one active project with the explicit ADMIN required by 0011."""

    project_id, principal_id, agent_type_id = uuid4(), uuid4(), uuid4()
    conn.execute(
        "INSERT INTO public.project (project_id, name, status) VALUES (%s, %s, 'active')",
        (project_id, f"schema-epoch-{project_id.hex}"),
    )
    conn.execute(
        "INSERT INTO public.principal (principal_id, kind, external_ref) VALUES (%s, 'oidc_sub', %s)",
        (principal_id, f"schema-epoch-{principal_id.hex}"),
    )
    conn.execute(
        "INSERT INTO public.agent_type (agent_type_id, project_id, name) VALUES (%s, %s, %s)",
        (agent_type_id, project_id, f"schema-epoch-{agent_type_id.hex}"),
    )
    conn.execute(
        "INSERT INTO public.agent_registration (principal_id, project_id, agent_type_id) VALUES (%s, %s, %s)",
        (principal_id, project_id, agent_type_id),
    )
    conn.execute(
        "INSERT INTO public.principal_grant (principal_id, project_id, role) VALUES (%s, %s, 'admin')",
        (principal_id, project_id),
    )
    return project_id


def _insert_c12_memory_chain(
    conn: psycopg.Connection[Any],
    *,
    project_id: UUID,
    principal_id: UUID,
    agent_type_id: UUID,
    root_subject_digests: tuple[bytes, ...],
) -> tuple[UUID, ...]:
    """Insert exactly 1,025 graph edges for an E2 depth-cap proof.

    The chain is fixture-owned data written before the request/bind under
    test.  Each link is acyclic, so the 1,025th edge is the first edge past
    E2's permitted depth 1,024 rather than a cycle artifact.
    """

    memory_ids = tuple(uuid4() for _ in range(1026))
    sentinel = subject_digest(ProjectId(project_id), PROJECT_SUBJECT_TAG)
    memory_rows = [
        (
            memory_id,
            project_id,
            agent_type_id,
            f"depth-proof-{project_id.hex}-{index}",
            f"{index:064x}",
            Jsonb({"class": "operator", "principal": str(principal_id)}),
            uuid4(),
            list(root_subject_digests if index == 0 else (sentinel,)),
        )
        for index, memory_id in enumerate(memory_ids)
    ]
    link_rows = [
        (project_id, memory_ids[index], memory_ids[index + 1], [sentinel]) for index in range(1025)
    ]
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO public.memory_item ("
            "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
            "content, content_hash, token_count, provenance, scan_verdict_id, subject_digests"
            ") VALUES (%s, %s, 'agent_type', %s, 'lesson', 'depth_proof', 'quality', 'B', "
            "'quarantined', %s, %s, 1, %s, %s, %s::bytea[])",
            memory_rows,
        )
        cur.executemany(
            "INSERT INTO public.memory_link (project_id, src_id, dst_id, relation, subject_digests) "
            "VALUES (%s, %s, %s, 'related', %s::bytea[])",
            link_rows,
        )
    return memory_ids


def _insert_authority_v1_trace_event(conn: psycopg.Connection[Any], project_id: object) -> None:
    """Exercise the API's v1 queue INSERT surface without EXECUTE on its trigger helper."""

    conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
    identity = conn.execute(
        "SELECT registration.principal_id, registration.agent_type_id, grant_row.grant_id "
        "FROM public.agent_registration AS registration "
        "JOIN public.principal_grant AS grant_row "
        "  ON grant_row.principal_id = registration.principal_id "
        " AND grant_row.project_id = registration.project_id "
        "WHERE registration.project_id = %s "
        "  AND registration.revoked_at IS NULL "
        "  AND grant_row.revoked_at IS NULL "
        "ORDER BY grant_row.grant_id "
        "LIMIT 1",
        (project_id,),
    ).fetchone()
    assert identity is not None
    principal_id, agent_type_id, grant_id = identity
    conn.execute(
        "INSERT INTO public.work_queue ("
        "project_id, topic, payload, authority_version, run_id, source_principal_id, "
        "source_agent_type_id, source_grant_id, required_role, run_owner_principal_id, "
        "run_owner_agent_type_id, subject_digests"
        ") VALUES ("
        "%s, 'trace_event', jsonb_build_object('seq', 1, 'event', '{}'::jsonb), 1, %s, %s, "
        "%s, %s, 'data', %s, %s, '{}'::bytea[]"
        ")",
        (project_id, uuid4(), principal_id, agent_type_id, grant_id, principal_id, agent_type_id),
    )


def _app_acl_surface(dsn: str) -> tuple[object, ...]:
    """Effective 0010 app surface, including every public child and yoyo table."""

    with psycopg.connect(dsn) as owner:
        tables = owner.execute(
            "SELECT relation.relname, relation.relkind, "
            "has_table_privilege('tracebed_app', relation.oid, 'SELECT'), "
            "has_table_privilege('tracebed_app', relation.oid, 'INSERT'), "
            "has_table_privilege('tracebed_app', relation.oid, 'UPDATE'), "
            "has_table_privilege('tracebed_app', relation.oid, 'DELETE') "
            "FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p') "
            "ORDER BY relation.relname, relation.relkind"
        ).fetchall()
        sequences = owner.execute(
            "SELECT relation.relname, has_sequence_privilege('tracebed_app', relation.oid, 'USAGE'), "
            "has_sequence_privilege('tracebed_app', relation.oid, 'SELECT') "
            "FROM pg_class AS relation JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'public' AND relation.relkind = 'S' ORDER BY relation.relname"
        ).fetchall()
        functions = owner.execute(
            "SELECT has_function_privilege('tracebed_app', "
            "'tokenizer_catalog.tokenize(text,text)'::regprocedure, 'EXECUTE'), "
            "has_function_privilege('tracebed_app', "
            "'bm25_catalog.to_bm25query(regclass,bm25_catalog.bm25vector)'::regprocedure, 'EXECUTE'), "
            "has_function_privilege('tracebed_app', "
            "'bm25_catalog.search_bm25query(bm25_catalog.bm25vector,bm25_catalog.bm25query)'::regprocedure, 'EXECUTE'), "
            "has_function_privilege('tracebed_app', 'public.cosine_distance(halfvec,halfvec)'::regprocedure, 'EXECUTE')"
        ).fetchone()
        schemas = owner.execute(
            "SELECT has_database_privilege('tracebed_app', current_database(), 'CONNECT'), "
            "has_schema_privilege('tracebed_app', 'public', 'USAGE'), "
            "has_schema_privilege('tracebed_app', 'tokenizer_catalog', 'USAGE'), "
            "has_schema_privilege('tracebed_app', 'bm25_catalog', 'USAGE')"
        ).fetchone()
    return (tables, sequences, functions, schemas)


def _assert_profile_fixture_matches_live_reference(
    conn: psycopg.Connection[Any], profile: str
) -> None:
    """Compare a disposable clean transition to the checked-in tuple fixture.

    The literal manifest is deliberately never generated during a migration.
    This proof supplies its auditable provenance instead: a clean dedicated
    PG18 reference traverses each supported authority state and must produce
    exactly the checked-in normalized ACL and schema tuple sets.
    """

    expected = conn.execute(
        "SELECT tuple_class, encode(tuple_digest, 'hex') "
        "FROM public.authority_acl_profile_tuple "
        "WHERE profile = %s::public.authority_acl_profile "
        "ORDER BY tuple_class, tuple_digest",
        (profile,),
    ).fetchall()
    actual = conn.execute(
        "WITH actual AS ("
        "  SELECT 'acl'::text AS tuple_class, tuple_digest "
        "  FROM public.authority_acl_profile_actual_tuples(%s::public.authority_acl_profile) "
        "  AS acl(tuple_digest) "
        "  UNION ALL "
        "  SELECT 'schema'::text AS tuple_class, tuple_digest "
        "  FROM public.authority_schema_profile_actual_tuples(%s::public.authority_acl_profile) "
        "  AS schema_profile(tuple_digest)"
        ") "
        "SELECT tuple_class, encode(tuple_digest, 'hex') "
        "FROM actual ORDER BY tuple_class, tuple_digest",
        (profile, profile),
    ).fetchall()
    assert actual == expected


def test_budgeted_activity_gate_retains_session_lock_across_short_transaction_without_guc_leak(
    dedicated_0011_dsn: str,
) -> None:
    """Exercise B2B2B.1 mechanics on the canonical disposable authority fixture."""

    class Budget:
        def remaining_ms(self) -> float:
            return 500.0

    assert isinstance(Budget(), RemainingBudget)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    activity_pool = create_activity_pool(
        api_dsn, connect_timeout_s=2, checkout_timeout_s=2.0, min_size=1, max_size=1
    )
    try:
        gate = ActivityGate(activity_pool, cleanup_timeout_ms=17)
        key = activity_lock_key(ProjectId(project_id))
        with (
            gate.shared(ProjectId(project_id), deadline=Budget()),
            psycopg.connect(api_dsn, autocommit=True) as observer,
        ):
            assert observer.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone() == (
                False,
            )
        with psycopg.connect(api_dsn, autocommit=True) as observer:
            assert observer.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone() == (True,)
            assert observer.execute("SELECT pg_advisory_unlock(%s)", (key,)).fetchone() == (True,)
        with activity_pool.connection() as conn:
            assert conn.execute("SHOW statement_timeout").fetchone() == ("0",)
            assert conn.execute("SHOW lock_timeout").fetchone() == ("0",)
    finally:
        activity_pool.close()


def test_attestation_inventory_activation_and_monotonic_activity(
    dedicated_0011_dsn: str,
) -> None:
    """No bypass: direct yoyo fails, an attested dedicated cutover is usable."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )

    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rolname, rolcanlogin FROM pg_roles "
            "WHERE rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker') ORDER BY rolname"
        ).fetchall() == [
            ("tracebed_api", True),
            ("tracebed_app", False),
            ("tracebed_worker", True),
        ]
        assert owner.execute(
            "SELECT has_database_privilege('tracebed_api', current_database(), 'CONNECT'), "
            "has_database_privilege('tracebed_api', 'postgres', 'CONNECT'), "
            "has_database_privilege('tracebed_api', current_database(), 'TEMP'), "
            "has_schema_privilege('tracebed_api', 'public', 'CREATE')"
        ).fetchone() == (True, False, False, False)
        assert owner.execute(
            "SELECT cutover_at IS NOT NULL, ingress_attested_at = cutover_at, "
            "activated_at IS NOT NULL, first_activity_at IS NULL "
            "FROM public.authority_cutover_state WHERE singleton"
        ).fetchone() == (True, True, True, True)
        assert owner.execute(
            "SELECT count(*), min(profile_version), "
            "bool_and(octet_length(source_acl_digest) = 32), "
            "bool_and(octet_length(result_acl_digest) = 32), "
            "bool_and(octet_length(source_schema_digest) = 32), "
            "bool_and(octet_length(result_schema_digest) = 32), "
            "bool_and(octet_length(receipt_digest) = 32) "
            "FROM public.authority_acl_epoch"
        ).fetchone() == (2, 2, True, True, True, True, True)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("CREATE TABLE public.cutover_bm25_probe (content bm25_catalog.bm25vector)")
        owner.execute(
            "CREATE INDEX cutover_bm25_probe_index ON public.cutover_bm25_probe "
            "USING bm25 (content bm25_catalog.bm25_ops)"
        )

    # The worker needs the concrete INSERT/UPDATE surface as well as the
    # halfvec typmod helper: this is a real partitioned memory write, not a
    # synthetic function-only ACL probe.
    memory_id = uuid4()
    vector_768 = "[" + ",".join("0" for _ in range(768)) + "]"
    with psycopg.connect(
        _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")
    ) as runtime:
        runtime.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        agent_type = runtime.execute(
            "SELECT agent_type_id FROM public.agent_type WHERE project_id = %s", (project_id,)
        ).fetchone()
        assert agent_type is not None
        runtime.execute(
            "INSERT INTO public.memory_item ("
            "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
            "content, content_hash, token_count, provenance, scan_verdict_id"
            ") VALUES (%s, %s, 'agent_type', %s, 'episodic', 'acl_live', 'operational', "
            "'A', 'candidate', %s, %s, 1, '{\"source\":\"cutover-live\"}'::jsonb, %s)",
            (
                memory_id,
                project_id,
                agent_type[0],
                "TAN1|ec=E|ti=tool|tv=v1|n=1|dur=1|pch=" + "0" * 64,
                "a" * 64,
                uuid4(),
            ),
        )
        runtime.execute(
            "UPDATE public.memory_item SET embedding = public.halfvec(%s::halfvec, 768, false), "
            "embedding_model_id = 'hash-local', embedding_model_version = 'v1' "
            "WHERE id = %s",
            (vector_768, memory_id),
        )
        runtime.commit()

    # API owns query assembly/search; worker owns tokenization and the halfvec
    # precision conversion used by embedding writes.  Exercise the two exact
    # allowlists independently rather than accidentally requiring API-only
    # cosine/BM25 search privileges from the worker.
    with psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")) as runtime:
        runtime.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        assert runtime.execute(
            "SELECT id, embedding IS NOT NULL, embedding_model_id, embedding_model_version "
            "FROM public.memory_item WHERE id = %s",
            (memory_id,),
        ).fetchone() == (memory_id, True, "hash-local", "v1")
        assert runtime.execute(
            "SELECT tokenizer_catalog.tokenize(%s, 'tracebed_lexical') IS NOT NULL",
            ("TAN1|ec=E|ti=tool|tv=v1|n=1|dur=1|pch=" + "0" * 64,),
        ).fetchone() == (True,)
        assert runtime.execute("SELECT ('[1,0]'::halfvec <=> '[1,0]'::halfvec) = 0").fetchone() == (
            True,
        )
        assert runtime.execute(
            "SELECT bm25_catalog.to_bm25query("
            "'public.cutover_bm25_probe_index'::regclass, "
            "tokenizer_catalog.tokenize(%s, 'tracebed_lexical')::bm25_catalog.bm25vector"
            ") IS NOT NULL",
            ("TAN1|ec=E|ti=tool|tv=v1|n=1|dur=1|pch=" + "0" * 64,),
        ).fetchone() == (True,)
        assert runtime.execute(
            "SELECT bm25_catalog.search_bm25query("
            "tokenizer_catalog.tokenize(%s, 'tracebed_lexical')::bm25_catalog.bm25vector, "
            "bm25_catalog.to_bm25query("
            "'public.cutover_bm25_probe_index'::regclass, "
            "tokenizer_catalog.tokenize(%s, 'tracebed_lexical')::bm25_catalog.bm25vector"
            ")"
            ") IS NOT NULL",
            (
                "TAN1|ec=E|ti=tool|tv=v1|n=1|dur=1|pch=" + "0" * 64,
                "TAN1|ec=E|ti=tool|tv=v1|n=1|dur=1|pch=" + "0" * 64,
            ),
        ).fetchone() == (True,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute(
                "SELECT bm25_catalog.bm25_page_inspect("
                "'public.cutover_bm25_probe_index'::regclass, 0)"
            )
        runtime.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute("SELECT tokenizer_catalog.create_tokenizer('cutover_forbidden', '{}')")
        runtime.rollback()

    with psycopg.connect(
        _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")
    ) as runtime:
        assert runtime.execute(
            "SELECT tokenizer_catalog.tokenize(%s, 'tracebed_lexical') IS NOT NULL",
            ("TAN1|ec=E|ti=tool|tv=v1|n=1|dur=1|pch=" + "0" * 64,),
        ).fetchone() == (True,)
        assert runtime.execute(
            "SELECT public.halfvec('[1,0]'::halfvec, 2, false) IS NOT NULL"
        ).fetchone() == (True,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute(
                "SELECT bm25_catalog.bm25_page_inspect("
                "'public.cutover_bm25_probe_index'::regclass, 0)"
            )
        runtime.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute("SELECT tokenizer_catalog.create_tokenizer('cutover_forbidden', '{}')")
        runtime.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute("SELECT public.tracebed_mark_authority_activity()")
        runtime.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute(
                "INSERT INTO public.work_queue (project_id, topic, payload) "
                "VALUES (%s, 'trace_event', '{}'::jsonb)",
                (project_id,),
            )
        runtime.rollback()

    with psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")) as api:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            api.execute("SELECT public.tracebed_mark_authority_activity()")
        api.rollback()
        _insert_authority_v1_trace_event(api, project_id)
        api.commit()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT activated_at IS NOT NULL, first_activity_at IS NOT NULL "
            "FROM public.authority_cutover_state WHERE singleton"
        ).fetchone() == (True, True)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        rollback_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"


def test_e1_live_validator_supported_receipt_and_rollback_fence(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the audited c12 validator, receipt, and rollback contracts.

    This is deliberately a direct c11→c12 migration path, rather than a
    source-text assertion: the array aggregates, Unicode semantic contract,
    receipt cursor, and preactivity-only rollback checks are PostgreSQL behavior.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        identity = owner.execute(
            "SELECT registration.principal_id, registration.agent_type_id, grant_row.grant_id "
            "FROM public.agent_registration AS registration "
            "JOIN public.principal_grant AS grant_row "
            "  ON grant_row.principal_id = registration.principal_id "
            " AND grant_row.project_id = registration.project_id "
            "WHERE registration.project_id = %s "
            "ORDER BY grant_row.grant_id LIMIT 1",
            (project_id,),
        ).fetchone()
        assert identity is not None
        owner.commit()
    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    # This test deliberately stops at the activated c11 state before E1's
    # forward preflight. The production bootstrap normally calls the general
    # runner first; replacing that already-completed no-op keeps it from
    # attempting the intentionally-not-yet-eligible 0012 transition.
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]

    # E1 deliberately does not publish a runtime. This owner-only activation
    # is a test setup for marker/transition behavior, not a service path.
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )

    tags = ("alice bob", "alice\u00a0bob", "   ", "alice\u0085bob")
    expected_python: list[bool] = []
    for tag in tags:
        try:
            validate_subject_tag(tag)
        except ValueError:
            expected_python.append(False)
        else:
            expected_python.append(True)

    principal_id, agent_type_id, _grant_id = identity
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        actual = owner.execute(
            "SELECT tracebed_subject_tag_is_valid(%s, false), "
            "tracebed_subject_tag_is_valid(%s, false), "
            "tracebed_subject_tag_is_valid(%s, false), "
            "tracebed_subject_tag_is_valid(%s, false), "
            "tracebed_envelope_versions_are_valid(ARRAY[]::smallint[]), "
            "tracebed_erasure_codes_are_valid(ARRAY[]::text[]), "
            "tracebed_erasure_codes_are_valid(ARRAY['a','b']::text[]), "
            "tracebed_erasure_codes_are_valid(ARRAY['b','a']::text[])",
            tags,
        ).fetchone()
        assert actual == (*expected_python, True, True, True, False)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_open_authority_admission()")
        erasure_grant = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'erasure_request') RETURNING grant_id",
            (principal_id, project_id),
        ).fetchone()
        assert erasure_grant is not None

    # Use the published E2 function to create its fenced request and
    # generation-zero receipt.  No direct owner request/phase mutation is a
    # supported E3 setup path.
    with psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")) as api:
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        accepted = api.execute(
            "SELECT request_id, phase, disposition, last_code FROM public.tracebed_request_erasure("
            "%s, %s, %s, %s, 'subject', 'e1-supported-receipt')",
            (project_id, principal_id, agent_type_id, erasure_grant[0]),
        ).fetchone()
        assert accepted is not None and accepted[1:] == ("fenced", "active", "in_progress")
        request_id = accepted[0]
        assert type(request_id) is UUID
        api.commit()

    with psycopg.connect(dedicated_0011_dsn) as owner:
        receipt = owner.execute(
            "SELECT step_seq, generation, previous_receipt_digest, receipt_digest "
            "FROM public.erasure_step_receipt WHERE request_id = %s",
            (request_id,),
        ).fetchone()
        assert receipt is not None and receipt[:3] == (1, 0, None)
        assert type(receipt[3]) is bytes and len(receipt[3]) == 32
        assert owner.execute(
            "SELECT first_activity_at IS NOT NULL FROM public.erasure_cutover_state WHERE singleton"
        ).fetchone() == (True,)

    # An accepted request/receipt is irreversible first activity.  The
    # preactivity-only rollback must reject it rather than erasing evidence.
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        rollback_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0012_erasure_saga"


def test_e2_live_seeded_c11_leaves_forward_to_c12_and_provision_22_leaves(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Seeded c11 leaves survive E2 and a c12 provision creates all 22.

    This is the profile regression behind the c12 ACL branch: the c11
    runtime matrix must continue to authenticate the original 17 leaves, and
    the E2-only families must authenticate their explicit empty leaf ACLs.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        seeded_project = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        identity = owner.execute(
            "SELECT principal_id, agent_type_id FROM public.agent_registration "
            "WHERE project_id = %s",
            (seeded_project,),
        ).fetchone()
        assert identity is not None
        seeded_run_id = uuid4()
        proposal_memory_id = uuid4()
        learning_memory_id = uuid4()
        parser_memory_id = uuid4()
        corroborated_memory_id = uuid4()
        trace_tag = "legacy-upgrade-trace"
        proposal_tag = "legacy-upgrade-proposal"
        learning_tag = "legacy-upgrade-learning"
        parser_tag = "legacy-upgrade-parser"
        corroborated_tag = "legacy-upgrade-corroborated"
        # Use actual c11 rows, rather than only empty leaves.  In particular,
        # c12 must build the attribution indexes before these backfill UPDATEs
        # or PG18 leaves them with indcheckxmin=true and rejects the c12
        # profile receipt.  The two memories also exercise both historical
        # run->memory forms: proposal provenance, parser trace_ids,
        # corroboration's bounded shadow runs, and a terminal learning job.
        owner.execute(
            "INSERT INTO public.run_owner "
            "(project_id, run_id, principal_id, agent_type_id, origin, bound_at) "
            "VALUES (%s, %s, %s, %s, 'trace', clock_timestamp())",
            (seeded_project, seeded_run_id, identity[0], identity[1]),
        )
        owner.execute(
            "INSERT INTO public.trace_subject (project_id, run_id, subject_tag) "
            "VALUES (%s, %s, %s)",
            (seeded_project, seeded_run_id, trace_tag),
        )
        for memory_id, subject_tag, provenance, shadow_runs in (
            (
                proposal_memory_id,
                proposal_tag,
                {"class": "proposal", "run_id": str(seeded_run_id)},
                [],
            ),
            (
                learning_memory_id,
                learning_tag,
                {"class": "operator", "principal": str(identity[0])},
                [],
            ),
            (
                parser_memory_id,
                parser_tag,
                {"class": "parser", "trace_ids": [str(seeded_run_id)]},
                [],
            ),
            (
                corroborated_memory_id,
                corroborated_tag,
                {"class": "operator", "principal": str(identity[0])},
                [seeded_run_id],
            ),
        ):
            owner.execute(
                "INSERT INTO public.memory_item ("
                "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
                "content, content_hash, token_count, subject_tag, provenance, scan_verdict_id, "
                "shadow_confirm_runs"
                ") VALUES (%s, %s, 'agent_type', %s, 'lesson', 'legacy_upgrade', 'quality', "
                "'B', 'quarantined', %s, repeat('a', 64), 1, %s, %s::jsonb, %s, %s::uuid[])",
                (
                    memory_id,
                    seeded_project,
                    identity[1],
                    f"legacy {memory_id}",
                    subject_tag,
                    Jsonb(provenance),
                    uuid4(),
                    shadow_runs,
                ),
            )
        owner.execute(
            "INSERT INTO public.trace_learning_job "
            "(project_id, run_id, pipeline, pipeline_version, trace_ended_at) "
            "VALUES (%s, %s, 'tier_a', 1, clock_timestamp())",
            (seeded_project, seeded_run_id),
        )
        owner.execute(
            "UPDATE public.trace_learning_job SET state = 'running', attempts = 1, "
            "lease_token = %s, lease_owner = 'legacy-upgrade', "
            "lease_expires_at = clock_timestamp() + interval '1 hour', "
            "first_started_at = clock_timestamp(), trace_digest = decode(repeat('ab', 32), 'hex') "
            "WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1",
            (uuid4(), seeded_project, seeded_run_id),
        )
        owner.execute(
            "UPDATE public.trace_learning_job SET state = 'succeeded', lease_token = NULL, "
            "lease_owner = NULL, lease_expires_at = NULL, "
            "result_digest = decode(repeat('cd', 32), 'hex'), memory_ids = ARRAY[%s]::uuid[], "
            "finished_at = clock_timestamp() "
            "WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1",
            (learning_memory_id, seeded_project, seeded_run_id),
        )
        owner.commit()
        assert owner.execute(
            "SELECT count(*) FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "WHERE parent.relname = ANY(%s)",
            (list(PARTITIONED_TABLES[:17]),),
        ).fetchone() == (17,)
    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0011') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0011') IS NOT NULL"
        ).fetchone() == (True, True)
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]

    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        seeded_children = owner.execute(
            "SELECT count(*) FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "WHERE parent.relname = ANY(%s)",
            (list(PARTITIONED_TABLES),),
        ).fetchone()
        assert seeded_children == (22,)
        assert owner.execute(
            "SELECT to_regclass(%s) IS NOT NULL",
            (partition_name("subject_fence", ProjectId(seeded_project)),),
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True)
        expected_indexes = [
            f"{partition_name('trace_subject', ProjectId(seeded_project))}_subject",
            f"{partition_name('run_owner', ProjectId(seeded_project))}_subjects",
            f"{partition_name('memory_item', ProjectId(seeded_project))}_subjects",
            f"{partition_name('trace_learning_job', ProjectId(seeded_project))}_subjects",
        ]
        assert owner.execute(
            "SELECT bool_and(NOT index_data.indcheckxmin) "
            "FROM pg_catalog.pg_index AS index_data "
            "JOIN pg_catalog.pg_class AS index_class ON index_class.oid = index_data.indexrelid "
            "WHERE index_class.relname = ANY(%s)",
            (expected_indexes,),
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT run_id, memory_id FROM public.run_memory_binding "
            "WHERE project_id = %s ORDER BY memory_id",
            (seeded_project,),
        ).fetchall() == sorted(
            [
                (seeded_run_id, proposal_memory_id),
                (seeded_run_id, learning_memory_id),
                (seeded_run_id, parser_memory_id),
                (seeded_run_id, corroborated_memory_id),
            ],
            key=lambda row: row[1].bytes,
        )
        expected_trace = subject_digest(ProjectId(seeded_project), trace_tag)
        assert owner.execute(
            "SELECT subject_digests FROM public.memory_item WHERE project_id = %s AND id = %s",
            (seeded_project, proposal_memory_id),
        ).fetchone() == (
            sorted(
                [
                    expected_trace,
                    subject_digest(ProjectId(seeded_project), proposal_tag),
                ]
            ),
        )
        assert owner.execute(
            "SELECT subject_digests FROM public.memory_item WHERE project_id = %s AND id = %s",
            (seeded_project, learning_memory_id),
        ).fetchone() == (
            sorted(
                [
                    expected_trace,
                    subject_digest(ProjectId(seeded_project), learning_tag),
                ]
            ),
        )
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )

    pool = create_pool(dedicated_0011_dsn, min_size=1, max_size=1)
    try:
        provisioned = ProjectProvisioner(pool, _E1Master(), FakeClock()).provision_project(
            name="e1-c12-leaves",
            retention_policy=None,
            idempotency_key_hash=uuid4().hex,
            request_hash=uuid4().hex,
        )
    finally:
        pool.close()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        for parent in PARTITIONED_TABLES:
            assert owner.execute(
                "SELECT to_regclass(%s) IS NOT NULL", (partition_name(parent, provisioned),)
            ).fetchone() == (True,)
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True)

    # Legacy proposal, parser, corroboration and learning edges are not merely
    # migration metadata. A real subject request must discover every bounded
    # form through the normalized binding in one fenced closure.
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_open_authority_admission()")
        erasure_grant = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'erasure_request') RETURNING grant_id",
            (identity[0], seeded_project),
        ).fetchone()
        assert erasure_grant is not None
    with psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")) as api:
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(seeded_project),))
        accepted = api.execute(
            "SELECT request_id, phase, disposition, last_code "
            "FROM public.tracebed_request_erasure(%s, %s, %s, %s, 'subject', %s)",
            (seeded_project, identity[0], identity[1], erasure_grant[0], trace_tag),
        ).fetchone()
        assert accepted is not None
        assert accepted[1:] == ("fenced", "active", "fenced")
        api.commit()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT memory_id FROM public.erase_mem_set WHERE project_id = %s ORDER BY memory_id",
            (seeded_project,),
        ).fetchall() == sorted(
            [
                (proposal_memory_id,),
                (learning_memory_id,),
                (parser_memory_id,),
                (corroborated_memory_id,),
            ],
            key=lambda row: row[0].bytes,
        )


def test_e2_active_request_revokes_legacy_runtime_trace_subject_dml(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """c12 removes a worker's residual trace-subject INSERT surface.

    This is intentionally raw SQL under the real worker LOGIN.  It models a
    stale or compromised code path which never called an authority helper.
    The normal c12 outcome is an ACL refusal before any table trigger; the
    durable gate remains the defence for residual write families.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
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

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )
        grant_id = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'erasure_request') RETURNING grant_id",
            (identity[0], project_id),
        ).fetchone()
        assert grant_id is not None
        owner.execute("SELECT public.tracebed_open_authority_admission()")
        seeded_run_id = uuid4()
        owner.execute(
            "INSERT INTO public.trace_subject (project_id, run_id, subject_tag, subject_digest) "
            "VALUES (%s, %s, NULL, public.tracebed_subject_digest(%s, 'runtime-direct-dml'))",
            (project_id, seeded_run_id, project_id),
        )
        owner.execute(
            "INSERT INTO public.killswitch_state (project_id, agent_type_id, mem_type, disabled) "
            "VALUES (%s, NULL, 'episodic', false)",
            (project_id,),
        )

    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    with psycopg.connect(api_dsn) as api:
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        request = api.execute(
            "SELECT request_id, phase, disposition FROM public.tracebed_request_erasure("
            "%s, %s, %s, %s, 'subject', 'runtime-direct-dml')",
            (project_id, identity[0], identity[1], grant_id[0]),
        ).fetchone()
        assert request is not None
        assert request[1:] == ("fenced", "active")
        api.commit()

    worker_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")
    forged_run_id = uuid4()
    with psycopg.connect(worker_dsn) as worker:
        worker.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        assert (
            worker.execute(
                "SELECT run_id FROM public.trace_subject WHERE project_id = %s",
                (project_id,),
            ).fetchall()
            == []
        )
        assert (
            worker.execute(
                "SELECT mem_type FROM public.killswitch_state WHERE project_id = %s",
                (project_id,),
            ).fetchall()
            == []
        )
        with pytest.raises(psycopg.Error) as refused:
            worker.execute(
                "INSERT INTO public.trace_subject "
                "(project_id, run_id, subject_tag, subject_digest) "
                "VALUES (%s, %s, NULL, decode(repeat('ab', 32), 'hex'))",
                (project_id, forged_run_id),
            )
        assert refused.value.sqlstate == "42501"
        worker.rollback()
        worker.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        with pytest.raises(psycopg.Error) as killswitch_refused:
            worker.execute(
                "INSERT INTO public.killswitch_state (project_id, agent_type_id, mem_type, disabled) "
                "VALUES (%s, NULL, 'semantic', false)",
                (project_id,),
            )
        assert killswitch_refused.value.sqlstate == "P0002"
        worker.rollback()

    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT EXISTS (SELECT 1 FROM public.erase_run_set "
            "WHERE project_id = %s AND run_id = %s)",
            (project_id, seeded_run_id),
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT NOT EXISTS (SELECT 1 FROM public.trace_subject "
            "WHERE project_id = %s AND run_id = %s)",
            (project_id, forged_run_id),
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT count(*) FROM public.killswitch_state WHERE project_id = %s",
            (project_id,),
        ).fetchone() == (1,)

    with pytest.raises(RuntimeError, match="rollback"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action="rollback-0012",
        )
    assert current_revision(dedicated_0011_dsn)[0] == "0012_erasure_saga"
    # A refusal preserves c12 evidence but leaves admissions deliberately
    # closed.  Reopening is an explicit authenticated owner action.
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="admission-open",
    )


def test_e2_c12_secdef_queue_scheduler_and_sentinel_are_live_safe(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise c12's only API admission and worker scheduler surfaces.

    This is deliberately real API/worker LOGIN traffic under FORCE RLS.  It
    proves that a raw producer cannot insert queue/owner rows, while the
    narrow API SECDEF function derives a typed trace tag, propagates its full
    union, gives an untagged run one durable project sentinel, and leaves the
    worker able to claim/dispose all three topics without a cross-project
    table scan.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        identity = owner.execute(
            "SELECT registration.principal_id, registration.agent_type_id "
            "FROM public.agent_registration AS registration "
            "WHERE registration.project_id = %s",
            (project_id,),
        ).fetchone()
        assert identity is not None
        # Keep a non-optional binding for the nested live API verifier below;
        # mypy deliberately does not retain narrowing of a captured variable.
        live_principal_id = identity[0]
        data_grant = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'data') RETURNING grant_id",
            (identity[0], project_id),
        ).fetchone()
        feedback_grant = owner.execute(
            "INSERT INTO public.principal_grant "
            "(principal_id, project_id, role, feedback_source) "
            "VALUES (%s, %s, 'feedback', 'verdict') RETURNING grant_id",
            (identity[0], project_id),
        ).fetchone()
        assert data_grant is not None and feedback_grant is not None
        # A second registered owner gives the mixed-batch regression a real
        # foreign run under the same project.  The API caller below has no
        # authority to bind it, while its other batch item is a late target.
        foreign_principal_id, foreign_agent_type_id = uuid4(), uuid4()
        owner.execute(
            "INSERT INTO public.principal (principal_id, kind, external_ref) VALUES (%s, 'oidc_sub', %s)",
            (foreign_principal_id, f"foreign-owner-{foreign_principal_id.hex}"),
        )
        owner.execute(
            "INSERT INTO public.agent_type (agent_type_id, project_id, name) VALUES (%s, %s, %s)",
            (foreign_agent_type_id, project_id, f"foreign-owner-{foreign_agent_type_id.hex}"),
        )
        owner.execute(
            "INSERT INTO public.agent_registration (principal_id, project_id, agent_type_id) "
            "VALUES (%s, %s, %s)",
            (foreign_principal_id, project_id, foreign_agent_type_id),
        )
        foreign_data_grant = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'data') RETURNING grant_id",
            (foreign_principal_id, project_id),
        ).fetchone()
        assert foreign_data_grant is not None
        ensure_schema_current(owner)
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    # Bootstrap owns the c11 runtime identity transition; keep pending c12
    # closed until its exact admission lifecycle has been observed.
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )
        owner.execute("SELECT public.tracebed_open_authority_admission()")

    data_access = AccessContext(
        project_id=ProjectId(project_id),
        agent_type_id=AgentTypeId(identity[1]),
        principal_id=PrincipalId(identity[0]),
        grants=(GrantBinding(data_grant[0], ProjectRole.DATA),),
    )
    feedback_access = AccessContext(
        project_id=ProjectId(project_id),
        agent_type_id=AgentTypeId(identity[1]),
        principal_id=PrincipalId(identity[0]),
        grants=(GrantBinding(feedback_grant[0], ProjectRole.FEEDBACK, FeedbackSource.VERDICT),),
    )
    foreign_data_access = AccessContext(
        project_id=ProjectId(project_id),
        agent_type_id=AgentTypeId(foreign_agent_type_id),
        principal_id=PrincipalId(foreign_principal_id),
        grants=(GrantBinding(foreign_data_grant[0], ProjectRole.DATA),),
    )
    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    worker_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")

    # Raw API DML cannot create a queue row or run owner after c12.  The
    # producer below must use the profiled function instead.
    with psycopg.connect(api_dsn) as api:
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            api.execute(
                "INSERT INTO public.run_owner "
                "(project_id, run_id, principal_id, agent_type_id, origin) "
                "VALUES (%s, %s, %s, %s, 'trace')",
                (project_id, uuid4(), identity[0], identity[1]),
            )
        api.rollback()
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            api.execute(
                "INSERT INTO public.work_queue (project_id, topic, payload) "
                "VALUES (%s, 'trace_event', '{}'::jsonb)",
                (project_id,),
            )
        api.rollback()
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            api.execute(
                "INSERT INTO public.invalidation_event "
                "(project_id, event_type, selector, subject_digests) "
                "VALUES (%s, 'forged_direct_write', '{}'::jsonb, "
                "ARRAY[decode(repeat('00', 32), 'hex')]::bytea[])",
                (project_id,),
            )
        api.rollback()

    api_pool = ConnectionPool(api_dsn, min_size=1, max_size=4, open=True)
    activity_pool = create_activity_pool(
        api_dsn, connect_timeout_s=2, checkout_timeout_s=2.0, min_size=1, max_size=2
    )
    worker_pool = ConnectionPool(worker_dsn, min_size=1, max_size=2, open=True)
    try:
        activity = ActivityGate(activity_pool)
        queue = AuthorizedWorkQueue(api_pool, FakeClock(), QueueConfig(), activity=activity)
        invalidation = AuthorizedInvalidationWriter(api_pool, FakeClock(), activity=activity)
        bound_run = RunId(uuid4())
        untagged_run = RunId(uuid4())
        trace_tag = "live-trace-subject"
        proposal_tag = "live-proposal-subject"
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    bound_run,
                    TraceQueuePayload(
                        seq=0,
                        event={
                            "type": "state_note",
                            "ts": "2026-01-01T00:00:00Z",
                            "payload": {"note": "bounded", "subject_tags": [trace_tag]},
                        },
                    ),
                ),
            ),
        )
        assert queue.enqueue_many_authorized(
            feedback_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_OUTCOME_EVENT,
                    bound_run,
                    OutcomeQueuePayload(
                        event_id=uuid4(), outcome="positive", payload={"kind": "verified"}
                    ),
                ),
            ),
        )
        # This binds a second direct tag and must propagate the complete
        # post-bind union to both earlier queue rows, including a leased row
        # if one existed.
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_MEMORY_PROPOSAL,
                    bound_run,
                    ProposalQueuePayload(
                        proposal={
                            "mem_type": "lesson",
                            "content": "bounded proposal",
                            "claimed_scope": "agent_type",
                            "subject_tag": proposal_tag,
                        }
                    ),
                ),
            ),
        )
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    untagged_run,
                    TraceQueuePayload(
                        seq=0,
                        event={
                            "type": "run_start",
                            "ts": "2026-01-01T00:00:00Z",
                            "payload": {},
                        },
                    ),
                ),
            ),
        )
        invalidation_id = invalidation.insert(data_access, "source_changed", {"scope": "project"})
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT subject_digests FROM public.invalidation_event "
                "WHERE project_id = %s AND event_id = %s",
                (project_id, invalidation_id),
            ).fetchone() == ([subject_digest(ProjectId(project_id), PROJECT_SUBJECT_TAG)],)

        with psycopg.connect(dedicated_0011_dsn) as owner:
            expected_bound = tuple(
                sorted(
                    (
                        subject_digest(ProjectId(project_id), trace_tag),
                        subject_digest(ProjectId(project_id), proposal_tag),
                    )
                )
            )
            assert owner.execute(
                "SELECT subject_digest FROM public.trace_subject "
                "WHERE project_id = %s AND run_id = %s ORDER BY subject_digest",
                (project_id, bound_run.value),
            ).fetchall() == [(digest,) for digest in expected_bound]
            assert owner.execute(
                "SELECT bool_and(subject_digests = %s::bytea[]) FROM public.work_queue "
                "WHERE project_id = %s AND run_id = %s",
                (list(expected_bound), project_id, bound_run.value),
            ).fetchone() == (True,)
            sentinel = subject_digest(ProjectId(project_id), PROJECT_SUBJECT_TAG)
            assert owner.execute(
                "SELECT subject_digest FROM public.trace_subject "
                "WHERE project_id = %s AND run_id = %s",
                (project_id, untagged_run.value),
            ).fetchall() == [(sentinel,)]
            assert owner.execute(
                "SELECT subject_digests FROM public.work_queue "
                "WHERE project_id = %s AND run_id = %s",
                (project_id, untagged_run.value),
            ).fetchone() == ([sentinel],)

        worker_queue = WorkerQueue(worker_pool, FakeClock(), QueueConfig())
        assert worker_queue.depth(TOPIC_TRACE_EVENT) == 2
        assert worker_queue.depth(TOPIC_OUTCOME_EVENT) == 1
        assert worker_queue.depth(TOPIC_MEMORY_PROPOSAL) == 1
        trace_items = worker_queue.claim(TOPIC_TRACE_EVENT, 2)
        assert {item.run_id for item in trace_items} == {bound_run, untagged_run}
        untagged_item = next(item for item in trace_items if item.run_id == untagged_run)
        bound_item = next(item for item in trace_items if item.run_id == bound_run)

        # The snapshot accepts the exact queue sentinel, proving an untagged
        # run has no stale-attribution P0003 retry loop.
        with psycopg.connect(worker_dsn) as worker:
            worker.execute(
                "SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),)
            )
            assert worker.execute(
                "SELECT public.tracebed_lock_run_subject_snapshot(%s, %s, %s::bytea[])",
                (project_id, untagged_run.value, list(untagged_item.subject_digests)),
            ).fetchone() == ([subject_digest(ProjectId(project_id), PROJECT_SUBJECT_TAG)],)
            worker.commit()
        assert worker_queue.nack(bound_item, timedelta(0)) is True
        assert worker_queue.ack(untagged_item) is True
        reclaimed = worker_queue.claim(TOPIC_TRACE_EVENT, 1)
        assert len(reclaimed) == 1 and reclaimed[0].run_id == bound_run
        assert worker_queue.ack(reclaimed[0]) is True

        outcome = worker_queue.claim(TOPIC_OUTCOME_EVENT, 1)
        assert len(outcome) == 1
        assert worker_queue.reject(outcome[0], "malformed_business_payload") is True
        assert worker_queue.dead_letter_count(TOPIC_OUTCOME_EVENT) == 1
        proposal = worker_queue.claim(TOPIC_MEMORY_PROPOSAL, 1)
        assert len(proposal) == 1 and worker_queue.ack(proposal[0]) is True

        # A real worker proposal write must append its normalized run→memory
        # edge in the very same transaction as the memory insert.  The later
        # subject request below proves the edge is also part of request
        # closure discovery, not merely an attribution decoration.
        proposal_clock = FakeClock()
        proposal_content = "A live worker proposal with durable lineage."
        proposal_item = NewMemoryItem(
            scope_type=ScopeType.AGENT_TYPE,
            scope_id=identity[1],
            mem_type=MemType.LESSON,
            kind="proposal",
            lane=Lane.QUALITY,
            trust_tier=TrustTier.B,
            status=Status.QUARANTINED,
            content=proposal_content,
            token_count=8,
            provenance=Provenance(cls=ProvenanceClass.PROPOSAL, run_id=bound_run),
        )
        verdict = scan(
            proposal_content,
            context=ScanContext(
                project_id=ProjectId(project_id),
                mem_type=proposal_item.mem_type,
                trust_tier=proposal_item.trust_tier,
                provenance_class=proposal_item.provenance.cls,
                lane=proposal_item.lane,
            ),
        ).verdict(clock=proposal_clock)
        proposal_result = Repo(worker_pool, proposal_clock).insert_proposal_within_caps(
            ProjectId(project_id),
            bound_run,
            proposal_item,
            verdict,
            per_run_cap=2,
            per_project_daily_cap=50,
            day=proposal_clock.now().date(),
            subject_digests=expected_bound,
        )
        assert proposal_result.outcome is ProposalCapOutcome.INSERTED
        assert proposal_result.memory_id is not None
        proposal_memory_id = proposal_result.memory_id
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT subject_digests FROM public.memory_item WHERE project_id = %s AND id = %s",
                (project_id, proposal_memory_id.value),
            ).fetchone() == (list(expected_bound),)
            assert owner.execute(
                "SELECT 1 FROM public.run_memory_binding "
                "WHERE project_id = %s AND run_id = %s AND memory_id = %s",
                (project_id, bound_run.value, proposal_memory_id.value),
            ).fetchone() == (1,)

        # Exercise the disclosure paths through the actual API role.  The
        # read gate retains the exact grant/project locks while each surface
        # runs its durable SECDEF predicates; those predicates must not need
        # direct ACLs on any erasure ledger/fence/set table.
        with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
            export_grant = owner.execute(
                "INSERT INTO public.principal_grant (principal_id, project_id, role) "
                "VALUES (%s, %s, 'export') RETURNING grant_id",
                (identity[0], project_id),
            ).fetchone()
            assert export_grant is not None

        class _LiveVerifier:
            def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
                del authorization
                if api_key != "live-c12":
                    raise AssertionError("the live route test supplied no test credential")
                return Principal(PrincipalId(live_principal_id), "oidc_sub", "live-c12")

        api_repo = Repo(api_pool, proposal_clock)
        read_gate = AuthorizedReadGate(api_pool, activity=activity)
        live_deps = AppDeps(
            verifier=_LiveVerifier(),
            resolver=api_repo,
            queue=queue,
            telemetry=SimpleNamespace(),
            memory_reader=api_repo,
            exporter=api_repo,
            invalidations=SimpleNamespace(),
            retrieval_opener=SimpleNamespace(),
            access_resolver=AuthorityStore(api_pool),
            clock=proposal_clock,
            control_plane=api_repo,
            read_gate=read_gate,
        )
        settings = TracebedSettings(
            storage=StorageConfig(pg_dsn="postgresql://unused@unused/unused"),
            embedding=EmbeddingConfig(model_version="test"),
        )
        app = create_app(settings, live_deps)
        app.state.reports_store = ReportsRepo(api_pool, proposal_clock)
        headers = {"x-api-key": "live-c12"}
        with TestClient(app) as client:
            assert (
                client.get(f"/admin/memory/{proposal_memory_id.value}", headers=headers).status_code
                == 200
            )
            exported = client.get("/export/project", headers=headers)
            assert exported.status_code == 200
            assert str(proposal_memory_id.value) in exported.text
            assert client.get("/admin/staleness/report", headers=headers).status_code == 200
        with read_gate.hold(data_access, ProjectRole.DATA):
            assert SearchStore(api_pool).corpus_size(ProjectId(project_id)) == 0

        # These are actual worker-login paths, not an owner fixture shortcut:
        # the learning claimant must evaluate its runtime fence helper under
        # FORCE RLS, and the lifecycle writer must retain the worker's normal
        # guarded mutation path.  A leaked direct erasure-table predicate or
        # a missing GUC/ACL would fail either operation here.
        with psycopg.connect(dedicated_0011_dsn) as owner:
            owner.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
            owner.execute(
                "INSERT INTO public.trace_learning_job ("
                "project_id, run_id, pipeline, pipeline_version, trace_ended_at, subject_digests"
                ") VALUES (%s, %s, %s, %s, clock_timestamp(), %s::bytea[])",
                (
                    project_id,
                    bound_run.value,
                    TIER_A_PIPELINE,
                    TIER_A_PIPELINE_VERSION,
                    list(expected_bound),
                ),
            )
            owner.commit()
        leases = TraceLearningJobStore(worker_pool).claim(
            ProjectId(project_id),
            TIER_A_PIPELINE,
            TIER_A_PIPELINE_VERSION,
            "live-c12-worker",
            1,
        )
        assert len(leases) == 1
        assert leases[0].run_id == bound_run
        assert leases[0].subject_digests == expected_bound
        LifecycleWriter(worker_pool, proposal_clock).persist_status(
            ProjectId(project_id),
            MemoryStatusWrite(
                memory_id=proposal_memory_id,
                from_status=Status.QUARANTINED,
                to_status=Status.CANDIDATE,
                now=proposal_clock.now(),
            ),
        )
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT status FROM public.memory_item WHERE project_id = %s AND id = %s",
                (project_id, proposal_memory_id.value),
            ).fetchone() == ("candidate",)

        # An unbound sentinel is a fallback, not a 65th identity.  Bind the
        # same 64 concrete tags trace-first and outcome/retrieval-first, then
        # bind a formerly sentinel-only memory to the latter run.  Both run
        # and memory unions must refine to the exact 64 real digests.
        refinement_tags = tuple(f"sentinel-refinement-{index:02d}" for index in range(64))
        refinement_digests = tuple(
            sorted(subject_digest(ProjectId(project_id), tag) for tag in refinement_tags)
        )
        trace_first_run = RunId(uuid4())
        sentinel_first_run = RunId(uuid4())
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    trace_first_run,
                    TraceQueuePayload(
                        seq=0,
                        event={
                            "type": "state_note",
                            "ts": "2026-01-01T00:00:00Z",
                            "payload": {
                                "note": "trace-first",
                                "subject_tags": list(refinement_tags),
                            },
                        },
                    ),
                ),
            ),
        )
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    sentinel_first_run,
                    TraceQueuePayload(
                        seq=0,
                        event={"type": "run_start", "ts": "2026-01-01T00:00:00Z", "payload": {}},
                    ),
                ),
            ),
        )
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    sentinel_first_run,
                    TraceQueuePayload(
                        seq=1,
                        event={
                            "type": "state_note",
                            "ts": "2026-01-01T00:00:01Z",
                            "payload": {
                                "note": "sentinel-first",
                                "subject_tags": list(refinement_tags),
                            },
                        },
                    ),
                ),
            ),
        )
        refinement_memory_id = uuid4()
        with psycopg.connect(dedicated_0011_dsn) as owner:
            owner.execute(
                "INSERT INTO public.memory_item ("
                "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
                "content, content_hash, token_count, provenance, scan_verdict_id, subject_digests"
                ") VALUES (%s, %s, 'agent_type', %s, 'lesson', 'sentinel_refinement', "
                "'quality', 'B', 'quarantined', 'sentinel refinement', repeat('c', 64), 1, "
                "jsonb_build_object('class', 'operator', 'principal', %s::text), %s, "
                "ARRAY[public.tracebed_subject_digest(%s, '__project__')]::bytea[])",
                (
                    refinement_memory_id,
                    project_id,
                    identity[1],
                    identity[0],
                    uuid4(),
                    project_id,
                ),
            )
            owner.commit()
        with psycopg.connect(worker_dsn) as worker:
            worker.execute(
                "SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),)
            )
            assert worker.execute(
                "SELECT public.tracebed_bind_run_memory(%s, %s, %s, %s::bytea[])",
                (
                    project_id,
                    sentinel_first_run.value,
                    refinement_memory_id,
                    list(refinement_digests),
                ),
            ).fetchone() == (list(refinement_digests),)
            worker.commit()
        with psycopg.connect(dedicated_0011_dsn) as owner:
            sentinel = subject_digest(ProjectId(project_id), PROJECT_SUBJECT_TAG)
            for run_id in (trace_first_run, sentinel_first_run):
                assert owner.execute(
                    "SELECT array_agg(subject_digest ORDER BY subject_digest) FROM public.trace_subject "
                    "WHERE project_id = %s AND run_id = %s",
                    (project_id, run_id.value),
                ).fetchone() == (list(refinement_digests),)
                assert owner.execute(
                    "SELECT bool_and(subject_digests = %s::bytea[]) FROM public.work_queue "
                    "WHERE project_id = %s AND run_id = %s",
                    (list(refinement_digests), project_id, run_id.value),
                ).fetchone() == (True,)
            assert owner.execute(
                "SELECT subject_digests FROM public.memory_item WHERE project_id = %s AND id = %s",
                (project_id, refinement_memory_id),
            ).fetchone() == (list(refinement_digests),)
            assert sentinel not in refinement_digests

        # Establish existing same-owner live/sentinel runs before the request.
        # An active subject request may never create a run, but these are the
        # narrow late-bind candidates exercised below through the real API
        # wrappers (not the raw low-level function).
        late_proposal_run = RunId(uuid4())
        late_retrieval_run = RunId(uuid4())
        late_retrieval_deadline_run = RunId(uuid4())
        late_outcome_run = RunId(uuid4())
        # Deterministic UUID order is intentional: the first mixed batch
        # reaches target containment before the foreign-owner refusal, while
        # the second reaches that refusal first and must still continue to its
        # target.  Caller order is the opposite in each case below.
        mixed_target_before_foreign = RunId(UUID(int=1))
        foreign_run = RunId(UUID(int=2))
        mixed_target_after_foreign = RunId(UUID(int=3))
        for late_run in (
            late_proposal_run,
            late_retrieval_run,
            late_retrieval_deadline_run,
            late_outcome_run,
            mixed_target_before_foreign,
            mixed_target_after_foreign,
        ):
            assert queue.enqueue_many_authorized(
                data_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        late_run,
                        TraceQueuePayload(
                            seq=0,
                            event={
                                "type": "run_start",
                                "ts": "2026-01-01T00:00:00Z",
                                "payload": {},
                            },
                        ),
                    ),
                ),
            )
        assert queue.enqueue_many_authorized(
            foreign_data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    foreign_run,
                    TraceQueuePayload(
                        seq=0,
                        event={
                            "type": "run_start",
                            "ts": "2026-01-01T00:00:00Z",
                            "payload": {},
                        },
                    ),
                ),
            ),
        )

        # Exercise the public HTTP boundary after all ordinary writes have
        # completed.  The route must use the same scoped authenticated grant
        # as the direct SQL proof, but must never return target/raw identity
        # data or distinguish an exact replay from first acceptance.
        with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
            erasure_grant = owner.execute(
                "INSERT INTO public.principal_grant (principal_id, project_id, role) "
                "VALUES (%s, %s, 'erasure_request') RETURNING grant_id",
                (identity[0], project_id),
            ).fetchone()
            assert erasure_grant is not None
        live_deps.erasure_requests = ErasureRequestStore(api_pool, activity=activity)
        with TestClient(app) as client:
            first = client.post(
                "/v1/erasure-requests",
                headers=headers,
                json={"scope": "subject", "subject_tag": trace_tag},
            )
            assert first.status_code == 202
            first_body = first.json()
            assert set(first_body) == {
                "request_id",
                "scope",
                "phase",
                "disposition",
                "last_code",
                "limitation_codes",
                "requested_at",
                "updated_at",
                "completed_at",
            }
            assert first_body["scope"] == "subject"
            assert first_body["phase"] == "fenced"
            assert first_body["disposition"] == "active"
            # The E3 requested→fenced trigger records the next worker state,
            # `in_progress`; fencing itself remains asserted above by phase.
            assert first_body["last_code"] == "in_progress"
            replay = client.post(
                "/v1/erasure-requests",
                headers=headers,
                json={"scope": "subject", "subject_tag": trace_tag},
            )
            assert replay.status_code == 202
            assert replay.json()["request_id"] == first_body["request_id"]
            status = client.get(f"/v1/erasure-requests/{first_body['request_id']}", headers=headers)
            assert status.status_code == 200
            assert status.json()["request_id"] == first_body["request_id"]

        # The wrapper-level regression: a late target tag is committed as
        # closure evidence even though each public operation is refused.  The
        # queue's preflight must leave its scoped transaction cleanly before
        # raising; retrieval follows the same rule while retaining its normal
        # shared-gate/transaction lifetime when writable.
        request_id = UUID(first_body["request_id"])
        target_digest = subject_digest(ProjectId(project_id), trace_tag)

        # A foreign run is an opaque 404 for this caller.  It must not roll
        # back a target run's late containment whether canonical run ordering
        # reaches the target before the foreign failure or afterward.  These
        # two calls also reverse the input order, so neither API order nor a
        # later typed error can decide whether closure is durable.
        mixed_counts: dict[RunId, int] = {}
        with psycopg.connect(dedicated_0011_dsn) as owner:
            for mixed_run in (
                mixed_target_before_foreign,
                foreign_run,
                mixed_target_after_foreign,
            ):
                mixed_count = owner.execute(
                    "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                    (project_id, mixed_run.value),
                ).fetchone()
                assert mixed_count is not None
                mixed_counts[mixed_run] = int(mixed_count[0])

        foreign_write = AuthorizedQueueWrite(
            TOPIC_TRACE_EVENT,
            foreign_run,
            TraceQueuePayload(
                seq=1,
                event={
                    "type": "run_start",
                    "ts": "2026-01-01T00:00:01Z",
                    "payload": {},
                },
            ),
        )
        target_before_write = AuthorizedQueueWrite(
            TOPIC_TRACE_EVENT,
            mixed_target_before_foreign,
            TraceQueuePayload(
                seq=1,
                event={
                    "type": "state_note",
                    "ts": "2026-01-01T00:00:01Z",
                    "payload": {"note": "mixed target", "subject_tags": [trace_tag]},
                },
            ),
        )
        target_after_write = AuthorizedQueueWrite(
            TOPIC_TRACE_EVENT,
            mixed_target_after_foreign,
            TraceQueuePayload(
                seq=1,
                event={
                    "type": "state_note",
                    "ts": "2026-01-01T00:00:01Z",
                    "payload": {"note": "mixed target", "subject_tags": [trace_tag]},
                },
            ),
        )
        for mixed_writes in (
            (foreign_write, target_before_write),
            (target_after_write, foreign_write),
        ):
            with pytest.raises(RunAuthorityDenied) as mixed_refusal:
                queue.enqueue_many_authorized(data_access, mixed_writes)
            assert trace_tag not in str(mixed_refusal.value)
            assert mixed_refusal.value.__cause__ is None

        with psycopg.connect(dedicated_0011_dsn) as owner:
            for mixed_target_run in (mixed_target_before_foreign, mixed_target_after_foreign):
                assert owner.execute(
                    "SELECT EXISTS (SELECT 1 FROM public.trace_subject "
                    "WHERE project_id = %s AND run_id = %s AND subject_digest = %s)",
                    (project_id, mixed_target_run.value, target_digest),
                ).fetchone() == (True,)
                assert owner.execute(
                    "SELECT state, request_id FROM public.run_fence "
                    "WHERE project_id = %s AND run_id = %s",
                    (project_id, mixed_target_run.value),
                ).fetchone() == ("fenced", request_id)
                assert owner.execute(
                    "SELECT EXISTS (SELECT 1 FROM public.erase_run_set "
                    "WHERE project_id = %s AND request_id = %s AND run_id = %s)",
                    (project_id, request_id, mixed_target_run.value),
                ).fetchone() == (True,)
                assert owner.execute(
                    "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                    (project_id, mixed_target_run.value),
                ).fetchone() == (mixed_counts[mixed_target_run],)
            assert owner.execute(
                "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                (project_id, foreign_run.value),
            ).fetchone() == (mixed_counts[foreign_run],)

        late_counts: dict[RunId, int] = {}
        with psycopg.connect(dedicated_0011_dsn) as owner:
            for late_run in (
                untagged_run,
                late_outcome_run,
                late_proposal_run,
                late_retrieval_run,
                late_retrieval_deadline_run,
            ):
                count_row = owner.execute(
                    "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                    (project_id, late_run.value),
                ).fetchone()
                assert count_row is not None
                late_counts[late_run] = int(count_row[0])
            retrieval_before = owner.execute(
                "SELECT count(*) FROM public.retrieval_event WHERE project_id = %s AND run_id = %s",
                (project_id, late_retrieval_run.value),
            ).fetchone()
            assert retrieval_before is not None

        # Trace binds the target on two live runs.  Both false outcomes must
        # commit; the second one becomes the outcome wrapper's full-union
        # fixture, because outcome payloads deliberately cannot carry tags.
        with pytest.raises(ErasureFenced):
            queue.enqueue_many_authorized(
                data_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        untagged_run,
                        TraceQueuePayload(
                            seq=1,
                            event={
                                "type": "state_note",
                                "ts": "2026-01-01T00:00:01Z",
                                "payload": {"note": "late", "subject_tags": [trace_tag]},
                            },
                        ),
                    ),
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        late_outcome_run,
                        TraceQueuePayload(
                            seq=1,
                            event={
                                "type": "state_note",
                                "ts": "2026-01-01T00:00:01Z",
                                "payload": {"note": "late", "subject_tags": [trace_tag]},
                            },
                        ),
                    ),
                ),
            )
        with pytest.raises(ErasureFenced):
            queue.enqueue_many_authorized(
                data_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_MEMORY_PROPOSAL,
                        late_proposal_run,
                        ProposalQueuePayload(
                            proposal={
                                "mem_type": "lesson",
                                "content": "late bind must be contained",
                                "claimed_scope": "agent_type",
                                "subject_tag": trace_tag,
                            }
                        ),
                    ),
                ),
            )
        retrieval_opener = AuthorizedRetrievalOpener(api_pool, activity=activity)
        # Preserve the historical no-deadline containment contract first.
        with pytest.raises(ErasureFenced):
            retrieval_opener.open(
                data_access,
                late_retrieval_run,
                subject_tags=(trace_tag,),
            )

        class _ExpiredAfterFalseBindBudget:
            remaining = 5_000.0

            def remaining_ms(self) -> float:
                return self.remaining

        budget = _ExpiredAfterFalseBindBudget()
        original_bind = retrieval_opener._runs.bind_subject_tags_outcome_on
        false_outcomes = 0

        def bind_then_expire(*args: object, **kwargs: object) -> object:
            nonlocal false_outcomes
            outcome = original_bind(*args, **kwargs)
            if not outcome.writable:
                false_outcomes += 1
                budget.remaining = 0.0
            return outcome

        monkeypatch.setattr(
            retrieval_opener._runs, "bind_subject_tags_outcome_on", bind_then_expire
        )
        with (
            pytest.raises(ErasureFenced),
            retrieval_opener.hold(
                data_access,
                late_retrieval_deadline_run,
                subject_tags=(trace_tag,),
                deadline=budget,
            ),
        ):
            raise AssertionError("a false bind must never yield an authority")
        assert false_outcomes == 1
        assert budget.remaining_ms() == 0.0
        # Outcomes have no caller tag; they inherit the already-fenced full
        # run union and must still commit no queue work before refusing.
        with pytest.raises(ErasureFenced):
            queue.enqueue_many_authorized(
                feedback_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_OUTCOME_EVENT,
                        late_outcome_run,
                        OutcomeQueuePayload(
                            event_id=uuid4(), outcome="positive", payload={"late": True}
                        ),
                    ),
                ),
            )

        with psycopg.connect(dedicated_0011_dsn) as owner:
            for late_run in (
                untagged_run,
                late_outcome_run,
                late_proposal_run,
                late_retrieval_run,
                late_retrieval_deadline_run,
            ):
                assert owner.execute(
                    "SELECT EXISTS (SELECT 1 FROM public.trace_subject "
                    "WHERE project_id = %s AND run_id = %s AND subject_digest = %s)",
                    (project_id, late_run.value, target_digest),
                ).fetchone() == (True,)
                assert owner.execute(
                    "SELECT state, request_id FROM public.run_fence "
                    "WHERE project_id = %s AND run_id = %s",
                    (project_id, late_run.value),
                ).fetchone() == ("fenced", request_id)
                assert owner.execute(
                    "SELECT EXISTS (SELECT 1 FROM public.erase_run_set "
                    "WHERE project_id = %s AND request_id = %s AND run_id = %s)",
                    (project_id, request_id, late_run.value),
                ).fetchone() == (True,)
                assert owner.execute(
                    "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                    (project_id, late_run.value),
                ).fetchone() == (late_counts[late_run],)
            assert (
                owner.execute(
                    "SELECT count(*) FROM public.retrieval_event WHERE project_id = %s AND run_id = %s",
                    (project_id, late_retrieval_run.value),
                ).fetchone()
                == retrieval_before
            )
    finally:
        api_pool.close()
        activity_pool.close()
        worker_pool.close()

    # A late discovery of the already-fenced subject attaches/fences the
    # existing untagged run instead of rolling the association back through
    # the generic activity trigger.  The profiled return intentionally never
    # discloses the blocking request id to the runtime caller.
    with psycopg.connect(api_dsn) as api:
        api.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        late = api.execute(
            "SELECT subject_digests, writable, blocking_request_id "
            "FROM public.tracebed_bind_run_subject_tags(%s, %s, %s, %s, %s, 'data', %s::text[])",
            (project_id, identity[0], identity[1], data_grant[0], untagged_run.value, [trace_tag]),
        ).fetchone()
        assert late is not None
        # A late concrete association refines the formerly-unbound sentinel;
        # it is not a 65th identity and no stale queue snapshot survives.
        assert late[0] == [subject_digest(ProjectId(project_id), trace_tag)]
        assert late[1:] == (False, None)
        api.commit()

    # The worker cannot issue a raw cross-project scan; global claim/metrics
    # are the only profiled scheduler surface and never return unclaimed rows.
    with psycopg.connect(worker_dsn) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute("SELECT project_id FROM public.work_queue")
        worker.rollback()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT EXISTS (SELECT 1 FROM public.erase_mem_set "
            "WHERE project_id = %s AND memory_id = %s)",
            (project_id, proposal_memory_id.value),
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT state FROM public.run_fence WHERE project_id = %s AND run_id = %s",
            (project_id, untagged_run.value),
        ).fetchone() == ("fenced",)
        assert owner.execute(
            "SELECT EXISTS (SELECT 1 FROM public.erase_run_set "
            "WHERE project_id = %s AND run_id = %s)",
            (project_id, untagged_run.value),
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True)


def test_e2_depth_cap_refuses_initial_and_late_closure_without_partial_state(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinned PG18 proof that E2 never truncates a 1,025-edge closure.

    The first project proves request acceptance rolls every initial fence/set
    write back.  The second proves a late bind rolls itself back, preserving
    the already-live sentinel run and its pre-existing request state.  The
    third proves a direct request cannot race between queue preflight/final
    admission and lose a later target closure.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    identity_rows: list[tuple[UUID, UUID, UUID, UUID]] = []
    with psycopg.connect(dedicated_0011_dsn) as owner:
        for _ in range(3):
            project_id = _create_active_project_admin(owner)
            identity = owner.execute(
                "SELECT principal_id, agent_type_id FROM public.agent_registration "
                "WHERE project_id = %s",
                (project_id,),
            ).fetchone()
            assert identity is not None
            data_grant = owner.execute(
                "INSERT INTO public.principal_grant (principal_id, project_id, role) "
                "VALUES (%s, %s, 'data') RETURNING grant_id",
                (identity[0], project_id),
            ).fetchone()
            assert data_grant is not None
            identity_rows.append((project_id, identity[0], identity[1], data_grant[0]))
        ensure_schema_current(owner)
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )
        erasure_grants: list[UUID] = []
        for project_id, principal_id, _agent_type_id, _data_grant in identity_rows:
            grant_row = owner.execute(
                "INSERT INTO public.principal_grant (principal_id, project_id, role) "
                "VALUES (%s, %s, 'erasure_request') RETURNING grant_id",
                (principal_id, project_id),
            ).fetchone()
            assert grant_row is not None
            erasure_grants.append(grant_row[0])
        owner.execute("SELECT public.tracebed_open_authority_admission()")

    initial_project, initial_principal, initial_agent, _initial_data_grant = identity_rows[0]
    late_project, late_principal, late_agent, late_data_grant = identity_rows[1]
    race_project, race_principal, race_agent, race_data_grant = identity_rows[2]
    initial_target = "depth-initial-target"
    late_target = "depth-late-target"
    race_target = "between-phases-target"
    initial_access = AccessContext(
        ProjectId(initial_project),
        AgentTypeId(initial_agent),
        PrincipalId(initial_principal),
        (GrantBinding(erasure_grants[0], ProjectRole.ERASURE_REQUEST),),
    )
    late_erasure_access = AccessContext(
        ProjectId(late_project),
        AgentTypeId(late_agent),
        PrincipalId(late_principal),
        (GrantBinding(erasure_grants[1], ProjectRole.ERASURE_REQUEST),),
    )
    late_data_access = AccessContext(
        ProjectId(late_project),
        AgentTypeId(late_agent),
        PrincipalId(late_principal),
        (GrantBinding(late_data_grant, ProjectRole.DATA),),
    )
    race_erasure_access = AccessContext(
        ProjectId(race_project),
        AgentTypeId(race_agent),
        PrincipalId(race_principal),
        (GrantBinding(erasure_grants[2], ProjectRole.ERASURE_REQUEST),),
    )
    race_data_access = AccessContext(
        ProjectId(race_project),
        AgentTypeId(race_agent),
        PrincipalId(race_principal),
        (GrantBinding(race_data_grant, ProjectRole.DATA),),
    )
    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    api_pool = ConnectionPool(api_dsn, min_size=1, max_size=4, open=True)
    activity_pool = create_activity_pool(
        api_dsn, connect_timeout_s=2, checkout_timeout_s=2.0, min_size=1, max_size=2
    )
    try:
        activity = ActivityGate(activity_pool)
        queue = AuthorizedWorkQueue(api_pool, FakeClock(), QueueConfig(), activity=activity)
        late_run = RunId(uuid4())
        # This ordinary run is live and explicitly project-attributed before
        # the request.  It is the state the late overflow must preserve.
        assert queue.enqueue_many_authorized(
            late_data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    late_run,
                    TraceQueuePayload(
                        seq=0,
                        event={
                            "type": "run_start",
                            "ts": "2026-01-01T00:00:00Z",
                            "payload": {},
                        },
                    ),
                ),
            ),
        )
        # Fill a separate existing owner with exactly 64 concrete identities.
        # Once the subject request is accepted, binding its target is the
        # capacity-overflow containment path: no 65th trace_subject row may
        # be admitted, but the run must still be attached and fenced.
        capacity_run = RunId(uuid4())
        capacity_tags = tuple(f"depth-capacity-{index:02d}" for index in range(64))
        capacity_digests = tuple(
            sorted(subject_digest(ProjectId(late_project), tag) for tag in capacity_tags)
        )
        assert queue.enqueue_many_authorized(
            late_data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    capacity_run,
                    TraceQueuePayload(
                        seq=0,
                        event={
                            "type": "state_note",
                            "ts": "2026-01-01T00:00:00Z",
                            "payload": {
                                "note": "capacity fixture",
                                "subject_tags": list(capacity_tags),
                            },
                        },
                    ),
                ),
            ),
        )

        initial_digest = subject_digest(ProjectId(initial_project), initial_target)
        late_sentinel = subject_digest(ProjectId(late_project), PROJECT_SUBJECT_TAG)
        with psycopg.connect(dedicated_0011_dsn) as owner:
            owner.execute(
                "SELECT set_config('tracebed.project_id', %s, true)", (str(initial_project),)
            )
            _insert_c12_memory_chain(
                owner,
                project_id=initial_project,
                principal_id=initial_principal,
                agent_type_id=initial_agent,
                root_subject_digests=(initial_digest,),
            )
            owner.execute(
                "SELECT set_config('tracebed.project_id', %s, true)", (str(late_project),)
            )
            late_memory_ids = _insert_c12_memory_chain(
                owner,
                project_id=late_project,
                principal_id=late_principal,
                agent_type_id=late_agent,
                root_subject_digests=(late_sentinel,),
            )
            owner.execute(
                "INSERT INTO public.run_memory_binding (project_id, run_id, memory_id) "
                "VALUES (%s, %s, %s)",
                (late_project, late_run.value, late_memory_ids[0]),
            )
            owner.commit()

        requests = ErasureRequestStore(api_pool, activity=activity)
        with pytest.raises(ErasureFenced) as initial_overflow:
            requests.request(initial_access, scope="subject", subject_tag=initial_target)
        assert "P0005" not in str(initial_overflow.value)
        assert initial_overflow.value.__cause__ is None
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT count(*) FROM public.erasure_request WHERE project_id = %s",
                (initial_project,),
            ).fetchone() == (0,)
            assert owner.execute(
                "SELECT count(*) FROM public.subject_fence WHERE project_id = %s AND state <> 'live'",
                (initial_project,),
            ).fetchone() == (0,)
            assert owner.execute(
                "SELECT count(*) FROM public.run_fence WHERE project_id = %s AND state <> 'live'",
                (initial_project,),
            ).fetchone() == (0,)
            assert owner.execute(
                "SELECT count(*) FROM public.erase_run_set WHERE project_id = %s",
                (initial_project,),
            ).fetchone() == (0,)
            assert owner.execute(
                "SELECT count(*) FROM public.erase_mem_set WHERE project_id = %s",
                (initial_project,),
            ).fetchone() == (0,)

        late_request = requests.request(
            late_erasure_access, scope="subject", subject_tag=late_target
        )
        late_digest = subject_digest(ProjectId(late_project), late_target)
        # A real retrieval opener reaches the same late-binder path.  The
        # profiled function may return a diagnostic 65-element attempted
        # union, but Python must let the transaction commit its containment
        # and only then raise the opaque refusal.
        with psycopg.connect(dedicated_0011_dsn) as owner:
            capacity_queue_before = owner.execute(
                "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                (late_project, capacity_run.value),
            ).fetchone()
            capacity_retrieval_before = owner.execute(
                "SELECT count(*) FROM public.retrieval_event WHERE project_id = %s AND run_id = %s",
                (late_project, capacity_run.value),
            ).fetchone()
            capacity_injection_before = owner.execute(
                "SELECT count(*) FROM public.injection_log WHERE project_id = %s AND run_id = %s",
                (late_project, capacity_run.value),
            ).fetchone()
            assert capacity_queue_before is not None
            assert capacity_retrieval_before is not None
            assert capacity_injection_before is not None
        capacity_opener = AuthorizedRetrievalOpener(api_pool, activity=activity)
        with pytest.raises(ErasureFenced) as capacity_refusal:
            capacity_opener.open(
                late_data_access,
                capacity_run,
                subject_tags=(late_target,),
            )
        assert "P000" not in str(capacity_refusal.value)
        assert late_target not in str(capacity_refusal.value)
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT array_agg(subject_digest ORDER BY subject_digest) FROM public.trace_subject "
                "WHERE project_id = %s AND run_id = %s",
                (late_project, capacity_run.value),
            ).fetchone() == (list(capacity_digests),)
            assert owner.execute(
                "SELECT count(*) FROM public.trace_subject WHERE project_id = %s AND run_id = %s",
                (late_project, capacity_run.value),
            ).fetchone() == (64,)
            assert owner.execute(
                "SELECT EXISTS (SELECT 1 FROM public.trace_subject "
                "WHERE project_id = %s AND run_id = %s AND subject_digest = %s)",
                (late_project, capacity_run.value, late_digest),
            ).fetchone() == (False,)
            assert owner.execute(
                "SELECT state, request_id FROM public.run_fence "
                "WHERE project_id = %s AND run_id = %s",
                (late_project, capacity_run.value),
            ).fetchone() == ("fenced", late_request.request_id)
            assert owner.execute(
                "SELECT EXISTS (SELECT 1 FROM public.erase_run_set "
                "WHERE project_id = %s AND request_id = %s AND run_id = %s)",
                (late_project, late_request.request_id, capacity_run.value),
            ).fetchone() == (True,)
            assert (
                owner.execute(
                    "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                    (late_project, capacity_run.value),
                ).fetchone()
                == capacity_queue_before
            )
            assert (
                owner.execute(
                    "SELECT count(*) FROM public.retrieval_event WHERE project_id = %s AND run_id = %s",
                    (late_project, capacity_run.value),
                ).fetchone()
                == capacity_retrieval_before
            )
            assert (
                owner.execute(
                    "SELECT count(*) FROM public.injection_log WHERE project_id = %s AND run_id = %s",
                    (late_project, capacity_run.value),
                ).fetchone()
                == capacity_injection_before
            )
        with pytest.raises(ErasureFenced) as late_overflow:
            queue.enqueue_many_authorized(
                late_data_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        late_run,
                        TraceQueuePayload(
                            seq=1,
                            event={
                                "type": "state_note",
                                "ts": "2026-01-01T00:00:01Z",
                                "payload": {"note": "depth", "subject_tags": [late_target]},
                            },
                        ),
                    ),
                ),
            )
        assert "P0005" not in str(late_overflow.value)
        assert late_overflow.value.__cause__ is None
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT array_agg(subject_digest ORDER BY subject_digest) FROM public.trace_subject "
                "WHERE project_id = %s AND run_id = %s",
                (late_project, late_run.value),
            ).fetchone() == ([late_sentinel],)
            assert owner.execute(
                "SELECT state, request_id FROM public.run_fence "
                "WHERE project_id = %s AND run_id = %s",
                (late_project, late_run.value),
            ).fetchone() == ("live", None)
            assert owner.execute(
                "SELECT EXISTS (SELECT 1 FROM public.trace_subject "
                "WHERE project_id = %s AND run_id = %s AND subject_digest = %s)",
                (late_project, late_run.value, late_digest),
            ).fetchone() == (False,)
            assert owner.execute(
                "SELECT count(*) FROM public.erase_run_set WHERE project_id = %s AND run_id = %s",
                (late_project, late_run.value),
            ).fetchone() == (0,)
            assert owner.execute(
                "SELECT count(*) FROM public.erase_mem_set "
                "WHERE project_id = %s AND request_id = %s",
                (late_project, late_request.request_id),
            ).fetchone() == (0,)

        # Deterministic inter-phase race: both runs preflight writable.  A
        # direct but authenticated erasure request then wins immediately
        # before the first final call.  The lower UUID has no target tag and
        # observes only the active request; the higher UUID carries the target
        # and must still be reached by the final no-enqueue containment sweep.
        race_unrelated_run = RunId(UUID(int=10))
        race_target_run = RunId(UUID(int=11))
        for race_run in (race_unrelated_run, race_target_run):
            assert queue.enqueue_many_authorized(
                race_data_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        race_run,
                        TraceQueuePayload(
                            seq=0,
                            event={
                                "type": "run_start",
                                "ts": "2026-01-01T00:00:00Z",
                                "payload": {},
                            },
                        ),
                    ),
                ),
            )
        original_call = queue._call_authorized_enqueue
        race_fired = False
        race_request_id: UUID | None = None

        def _request_between_preflight_and_final(
            *args: Any, **kwargs: Any
        ) -> tuple[int | None, bool]:
            nonlocal race_fired, race_request_id
            if kwargs.get("enqueue") is True and not race_fired:
                race_fired = True
                erasure_grant = race_erasure_access.grant_for(ProjectRole.ERASURE_REQUEST)
                assert erasure_grant is not None
                with psycopg.connect(api_dsn) as direct:
                    direct.execute(
                        "SELECT set_config('tracebed.project_id', %s, true)",
                        (str(race_project),),
                    )
                    row = direct.execute(
                        "SELECT request_id FROM public.tracebed_request_erasure("
                        "%s, %s, %s, %s, 'subject', %s)",
                        (
                            race_project,
                            race_erasure_access.principal_id.value,
                            race_erasure_access.agent_type_id.value,
                            erasure_grant.grant_id,
                            race_target,
                        ),
                    ).fetchone()
                    assert row is not None and type(row[0]) is UUID
                    race_request_id = row[0]
                    direct.commit()
            return original_call(*args, **kwargs)

        monkeypatch.setattr(queue, "_call_authorized_enqueue", _request_between_preflight_and_final)
        with pytest.raises(ErasureFenced) as interphase_refusal:
            queue.enqueue_many_authorized(
                race_data_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        race_target_run,
                        TraceQueuePayload(
                            seq=1,
                            event={
                                "type": "state_note",
                                "ts": "2026-01-01T00:00:01Z",
                                "payload": {"note": "target", "subject_tags": [race_target]},
                            },
                        ),
                    ),
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        race_unrelated_run,
                        TraceQueuePayload(
                            seq=1,
                            event={
                                "type": "state_note",
                                "ts": "2026-01-01T00:00:01Z",
                                "payload": {"note": "unrelated"},
                            },
                        ),
                    ),
                ),
            )
        assert race_fired and race_request_id is not None
        assert race_target not in str(interphase_refusal.value)
        race_digest = subject_digest(ProjectId(race_project), race_target)
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT EXISTS (SELECT 1 FROM public.trace_subject "
                "WHERE project_id = %s AND run_id = %s AND subject_digest = %s)",
                (race_project, race_target_run.value, race_digest),
            ).fetchone() == (True,)
            assert owner.execute(
                "SELECT state, request_id FROM public.run_fence "
                "WHERE project_id = %s AND run_id = %s",
                (race_project, race_target_run.value),
            ).fetchone() == ("fenced", race_request_id)
            assert owner.execute(
                "SELECT EXISTS (SELECT 1 FROM public.erase_run_set "
                "WHERE project_id = %s AND request_id = %s AND run_id = %s)",
                (race_project, race_request_id, race_target_run.value),
            ).fetchone() == (True,)
            assert owner.execute(
                "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                (race_project, race_unrelated_run.value),
            ).fetchone() == (1,)
            assert owner.execute(
                "SELECT count(*) FROM public.work_queue WHERE project_id = %s AND run_id = %s",
                (race_project, race_target_run.value),
            ).fetchone() == (1,)
    finally:
        api_pool.close()
        activity_pool.close()


def test_e2_worker_scheduler_skips_fenced_prefixes_for_every_topic(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fenced priority prefix must not starve another project's ready work.

    This is the live regression for the old ``LIMIT n * 8``-then-skip
    scheduler shape.  Each topic has eight earlier A rows that become
    durably fenced, followed by one B row.  A global worker may learn no
    cross-project rows, but it must still claim B rather than rescan A
    forever under FORCE RLS.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    identities: list[tuple[UUID, tuple[UUID, UUID], tuple[UUID, UUID], UUID]] = []
    with psycopg.connect(dedicated_0011_dsn) as owner:
        for _label in ("blocked", "ready"):
            project_id = _create_active_project_admin(owner)
            identity = owner.execute(
                "SELECT principal_id, agent_type_id FROM public.agent_registration "
                "WHERE project_id = %s",
                (project_id,),
            ).fetchone()
            assert identity is not None
            data_grant = owner.execute(
                "INSERT INTO public.principal_grant (principal_id, project_id, role) "
                "VALUES (%s, %s, 'data') RETURNING grant_id",
                (identity[0], project_id),
            ).fetchone()
            feedback_grant = owner.execute(
                "INSERT INTO public.principal_grant "
                "(principal_id, project_id, role, feedback_source) "
                "VALUES (%s, %s, 'feedback', 'verdict') RETURNING grant_id",
                (identity[0], project_id),
            ).fetchone()
            assert data_grant is not None and feedback_grant is not None
            identities.append(
                (
                    project_id,
                    (identity[0], identity[1]),
                    (data_grant[0], feedback_grant[0]),
                    uuid4(),
                )
            )
        ensure_schema_current(owner)
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]
    blocked_project, blocked_identity, blocked_grants, _ = identities[0]
    ready_project, ready_identity, ready_grants, _ = identities[1]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )
        erasure_grant = owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) "
            "VALUES (%s, %s, 'erasure_request') RETURNING grant_id",
            (blocked_identity[0], blocked_project),
        ).fetchone()
        assert erasure_grant is not None
        owner.execute("SELECT public.tracebed_open_authority_admission()")

    blocked_data = AccessContext(
        ProjectId(blocked_project),
        AgentTypeId(blocked_identity[1]),
        PrincipalId(blocked_identity[0]),
        (GrantBinding(blocked_grants[0], ProjectRole.DATA),),
    )
    blocked_feedback = AccessContext(
        ProjectId(blocked_project),
        AgentTypeId(blocked_identity[1]),
        PrincipalId(blocked_identity[0]),
        (GrantBinding(blocked_grants[1], ProjectRole.FEEDBACK, FeedbackSource.VERDICT),),
    )
    blocked_erasure = AccessContext(
        ProjectId(blocked_project),
        AgentTypeId(blocked_identity[1]),
        PrincipalId(blocked_identity[0]),
        (GrantBinding(erasure_grant[0], ProjectRole.ERASURE_REQUEST),),
    )
    ready_data = AccessContext(
        ProjectId(ready_project),
        AgentTypeId(ready_identity[1]),
        PrincipalId(ready_identity[0]),
        (GrantBinding(ready_grants[0], ProjectRole.DATA),),
    )
    ready_feedback = AccessContext(
        ProjectId(ready_project),
        AgentTypeId(ready_identity[1]),
        PrincipalId(ready_identity[0]),
        (GrantBinding(ready_grants[1], ProjectRole.FEEDBACK, FeedbackSource.VERDICT),),
    )
    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    worker_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")
    api_pool = ConnectionPool(api_dsn, min_size=1, max_size=4, open=True)
    activity_pool = create_activity_pool(
        api_dsn, connect_timeout_s=2, checkout_timeout_s=2.0, min_size=1, max_size=2
    )
    worker_pool = ConnectionPool(worker_dsn, min_size=1, max_size=2, open=True)
    try:
        gate = ActivityGate(activity_pool)
        queue = AuthorizedWorkQueue(api_pool, FakeClock(), QueueConfig(), activity=gate)
        blocked_tag = "scheduler-fenced-prefix"
        trace_runs = tuple(RunId(uuid4()) for _ in range(8))
        assert queue.enqueue_many_authorized(
            blocked_data,
            tuple(
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    run_id,
                    TraceQueuePayload(
                        seq=0,
                        event={
                            "type": "state_note",
                            "ts": "2026-01-01T00:00:00Z",
                            "payload": {"note": "blocked", "subject_tags": [blocked_tag]},
                        },
                    ),
                )
                for run_id in trace_runs
            ),
        )
        ready_trace_run = RunId(uuid4())
        assert queue.enqueue_many_authorized(
            ready_data,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    ready_trace_run,
                    TraceQueuePayload(
                        seq=0,
                        event={"type": "run_start", "ts": "2026-01-01T00:00:00Z", "payload": {}},
                    ),
                ),
            ),
        )

        # Outcome rows inherit their already-bound trace union; proposals
        # carry the direct tag.  Both form the same blocked prefix pattern.
        for run_id in trace_runs:
            assert queue.enqueue_many_authorized(
                blocked_feedback,
                (
                    AuthorizedQueueWrite(
                        TOPIC_OUTCOME_EVENT,
                        run_id,
                        OutcomeQueuePayload(
                            event_id=uuid4(), outcome="positive", payload={"kind": "blocked"}
                        ),
                    ),
                ),
            )
        assert queue.enqueue_many_authorized(
            ready_feedback,
            (
                AuthorizedQueueWrite(
                    TOPIC_OUTCOME_EVENT,
                    ready_trace_run,
                    OutcomeQueuePayload(
                        event_id=uuid4(), outcome="positive", payload={"kind": "ready"}
                    ),
                ),
            ),
        )
        for run_id in trace_runs:
            assert queue.enqueue_many_authorized(
                blocked_data,
                (
                    AuthorizedQueueWrite(
                        TOPIC_MEMORY_PROPOSAL,
                        run_id,
                        ProposalQueuePayload(
                            proposal={
                                "mem_type": "lesson",
                                "content": "blocked proposal",
                                "claimed_scope": "agent_type",
                                "subject_tag": blocked_tag,
                            }
                        ),
                    ),
                ),
            )
        assert queue.enqueue_many_authorized(
            ready_data,
            (
                AuthorizedQueueWrite(
                    TOPIC_MEMORY_PROPOSAL,
                    ready_trace_run,
                    ProposalQueuePayload(
                        proposal={
                            "mem_type": "lesson",
                            "content": "ready proposal",
                            "claimed_scope": "agent_type",
                        }
                    ),
                ),
            ),
        )

        status = ErasureRequestStore(api_pool, activity=gate).request(
            blocked_erasure, scope="subject", subject_tag=blocked_tag
        )
        assert status.phase == "fenced"

        worker_queue = WorkerQueue(worker_pool, FakeClock(), QueueConfig())
        for topic in (TOPIC_TRACE_EVENT, TOPIC_OUTCOME_EVENT, TOPIC_MEMORY_PROPOSAL):
            assert worker_queue.depth(topic) == 9
            claimed = worker_queue.claim(topic, 1)
            assert len(claimed) == 1
            assert claimed[0].project_id == ProjectId(ready_project)
            assert worker_queue.ack(claimed[0]) is True
            # The remaining eight rows belong to the fenced project, so a
            # second claim proves we moved beyond its entire prefix rather
            # than merely getting lucky with an over-fetch multiplier.
            assert worker_queue.claim(topic, 1) == []
            assert worker_queue.depth(topic) == 8
    finally:
        api_pool.close()
        activity_pool.close()
        worker_pool.close()


def test_e2_concurrent_first_activity_writes_are_both_accepted(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one-time activity receipt cannot reject an unrelated first write.

    Hold the singleton so two real API SECDEF invalidation writes both reach
    the conditional marker update.  Once it is released, one writer sets the
    receipt and the other must re-read it as a valid winner rather than fail
    with the old 42501 race.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    identities: list[tuple[UUID, UUID, UUID, UUID]] = []
    with psycopg.connect(dedicated_0011_dsn) as owner:
        for _ in range(2):
            project_id = _create_active_project_admin(owner)
            identity = owner.execute(
                "SELECT principal_id, agent_type_id FROM public.agent_registration "
                "WHERE project_id = %s",
                (project_id,),
            ).fetchone()
            assert identity is not None
            grant = owner.execute(
                "INSERT INTO public.principal_grant (principal_id, project_id, role) "
                "VALUES (%s, %s, 'data') RETURNING grant_id",
                (identity[0], project_id),
            ).fetchone()
            assert grant is not None
            identities.append((project_id, identity[0], identity[1], grant[0]))
        ensure_schema_current(owner)
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )
        owner.execute("SELECT public.tracebed_open_authority_admission()")

    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    started = threading.Barrier(2)
    errors: list[BaseException] = []
    event_ids: list[UUID] = []
    results_lock = threading.Lock()

    def _write(identity: tuple[UUID, UUID, UUID, UUID]) -> None:
        project_id, principal_id, agent_type_id, grant_id = identity
        try:
            with psycopg.connect(api_dsn) as api:
                api.execute(
                    "SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),)
                )
                started.wait(timeout=2)
                row = api.execute(
                    "SELECT public.tracebed_insert_authorized_invalidation("
                    "%s, %s, %s, %s, 'concurrent_first_write', '{\"scope\":\"project\"}'::jsonb)",
                    (project_id, principal_id, agent_type_id, grant_id),
                ).fetchone()
                assert row is not None and type(row[0]) is UUID
                api.commit()
                with results_lock:
                    event_ids.append(row[0])
        except BaseException as exc:  # capture thread assertion/DB failure for the parent test
            with results_lock:
                errors.append(exc)

    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT first_activity_at IS NULL FROM public.erasure_cutover_state WHERE singleton FOR UPDATE"
        ).fetchone() == (True,)
        threads = [threading.Thread(target=_write, args=(identity,)) for identity in identities]
        for thread in threads:
            thread.start()
        # Both API calls have crossed their barrier and must wait on the
        # singleton marker row, not each other through a permanent hot lock.
        time.sleep(0.15)
        assert all(thread.is_alive() for thread in threads)
        owner.commit()
    for thread in threads:
        thread.join(timeout=3)
        assert not thread.is_alive()
    assert errors == []
    assert len(event_ids) == 2 and len(set(event_ids)) == 2
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT first_activity_at IS NOT NULL FROM public.erasure_cutover_state WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT count(*) FROM public.invalidation_event WHERE event_id = ANY(%s::uuid[])",
            (event_ids,),
        ).fetchone() == (2,)


def test_e2_rollback_accepts_exact_nonempty_c11_run_memory_baseline(
    dedicated_0011_dsn: str,
) -> None:
    """Migration-created legacy bindings remain eligible for preactivity rollback.

    The c12 baseline contains both a legacy proposal provenance edge and a
    terminal learning-job edge.  It must authenticate through the immutable
    receipt rather than being rejected merely because run_memory_binding is
    nonempty.
    """

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        identity = owner.execute(
            "SELECT principal_id, agent_type_id FROM public.agent_registration "
            "WHERE project_id = %s",
            (project_id,),
        ).fetchone()
        assert identity is not None
        ensure_schema_current(owner)
        run_id = uuid4()
        proposal_memory_id, learning_memory_id, runtime_memory_id = uuid4(), uuid4(), uuid4()
        owner.execute(
            "INSERT INTO public.run_owner "
            "(project_id, run_id, principal_id, agent_type_id, origin, bound_at) "
            "VALUES (%s, %s, %s, %s, 'trace', clock_timestamp())",
            (project_id, run_id, identity[0], identity[1]),
        )
        owner.execute(
            "INSERT INTO public.trace_subject (project_id, run_id, subject_tag) "
            "VALUES (%s, %s, 'rollback-baseline-subject')",
            (project_id, run_id),
        )
        for memory_id, provenance in (
            (proposal_memory_id, {"class": "proposal", "run_id": str(run_id)}),
            (learning_memory_id, {"class": "operator", "principal": str(identity[0])}),
            (runtime_memory_id, {"class": "operator", "principal": str(identity[0])}),
        ):
            owner.execute(
                "INSERT INTO public.memory_item ("
                "id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, "
                "content, content_hash, token_count, provenance, scan_verdict_id"
                ") VALUES (%s, %s, 'agent_type', %s, 'lesson', 'rollback_baseline', "
                "'quality', 'B', 'quarantined', 'legacy baseline', repeat('b', 64), 1, %s::jsonb, %s)",
                (memory_id, project_id, identity[1], Jsonb(provenance), uuid4()),
            )
        owner.execute(
            "INSERT INTO public.trace_learning_job "
            "(project_id, run_id, pipeline, pipeline_version, trace_ended_at) "
            "VALUES (%s, %s, 'tier_a', 1, clock_timestamp())",
            (project_id, run_id),
        )
        owner.execute(
            "UPDATE public.trace_learning_job SET state = 'running', attempts = 1, "
            "lease_token = %s, lease_owner = 'rollback-baseline', "
            "lease_expires_at = clock_timestamp() + interval '1 hour', "
            "first_started_at = clock_timestamp(), trace_digest = decode(repeat('ab', 32), 'hex') "
            "WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1",
            (uuid4(), project_id, run_id),
        )
        owner.execute(
            "UPDATE public.trace_learning_job SET state = 'succeeded', lease_token = NULL, "
            "lease_owner = NULL, lease_expires_at = NULL, "
            "result_digest = decode(repeat('cd', 32), 'hex'), memory_ids = ARRAY[%s]::uuid[], "
            "finished_at = clock_timestamp() "
            "WHERE project_id = %s AND run_id = %s AND pipeline = 'tier_a' AND pipeline_version = 1",
            (learning_memory_id, project_id, run_id),
        )
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="cutover-0012",
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT legacy_run_memory_binding_rows, first_activity_at IS NULL "
            "FROM public.erasure_cutover_state WHERE singleton"
        ).fetchone() == (2, True)
        assert owner.execute(
            "SELECT run_id, memory_id FROM public.run_memory_binding "
            "WHERE project_id = %s ORDER BY memory_id",
            (project_id,),
        ).fetchall() == sorted(
            [(run_id, proposal_memory_id), (run_id, learning_memory_id)],
            key=lambda row: row[1].bytes,
        )

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="rollback-0012",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT to_regclass('public.run_memory_binding') IS NULL"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0011') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0011') IS NOT NULL"
        ).fetchone() == (True, True)

    # A second clean cutover replays the exact two-edge migration baseline.
    # A real worker-only append afterwards is runtime activity and therefore
    # irreversibly blocks rollback; it must not be mistaken for that receipt.
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="cutover-0012",
    )
    worker_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")
    expected_digest = subject_digest(ProjectId(project_id), "rollback-baseline-subject")
    with psycopg.connect(worker_dsn) as worker:
        worker.execute("SELECT set_config('tracebed.project_id', %s, false)", (str(project_id),))
        assert worker.execute(
            "SELECT public.tracebed_bind_run_memory(%s, %s, %s, %s::bytea[])",
            (project_id, run_id, runtime_memory_id, [expected_digest]),
        ).fetchone() == ([expected_digest],)
        worker.commit()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT legacy_run_memory_binding_rows, first_activity_at IS NOT NULL "
            "FROM public.erasure_cutover_state WHERE singleton"
        ).fetchone() == (2, True)
        assert owner.execute(
            "SELECT count(*) FROM public.run_memory_binding WHERE project_id = %s",
            (project_id,),
        ).fetchone() == (3,)
    with pytest.raises(RuntimeError, match="rollback"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action="rollback-0012",
        )
    assert current_revision(dedicated_0011_dsn)[0] == "0012_erasure_saga"


def test_e2_bootstrap_cutover_rollback_and_reapply_lifecycle(
    dedicated_0011_dsn: str,
) -> None:
    """The owner action, not ordinary startup, owns c11↔c12 transitions."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="cutover-0012",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0012_erasure_saga"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT activated_at IS NOT NULL, rollback_quarantined_at IS NULL, "
            "first_activity_at IS NULL FROM public.erasure_cutover_state WHERE singleton"
        ).fetchone() == (True, True, True)
        assert owner.execute(
            "SELECT admissions_open FROM public.authority_admission_state WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0012') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0012') IS NOT NULL"
        ).fetchone() == (True, True)

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="rollback-0012",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT to_regclass('public.erasure_cutover_state') IS NULL"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT public.authority_acl_security_assert('cutover_0011') IS NOT NULL, "
            "public.authority_schema_security_assert('cutover_0011') IS NOT NULL"
        ).fetchone() == (True, True)

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="cutover-0012",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0012_erasure_saga"


def test_split_runtime_readiness_requires_exact_role_and_cleans_pool_project_guc(
    dedicated_0011_dsn: str,
) -> None:
    """B3 accepts only the activated exact runtime identities on real PG18."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )

    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    worker_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")
    for dsn, role, expected_privileges in (
        (api_dsn, "tracebed_api", (True, False, True)),
        (worker_dsn, "tracebed_worker", (False, True, False)),
    ):
        with psycopg.connect(dsn, autocommit=True) as runtime:
            assert runtime.execute(
                "SELECT session_user, current_user, "
                "public.tracebed_runtime_prepublication_readiness() IS NULL"
            ).fetchone() == (role, role, False)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                runtime.execute("SELECT public.tracebed_runtime_readiness()")
            assert (
                runtime.execute(
                    "SELECT has_table_privilege(session_user, 'public.work_queue', 'INSERT'), "
                    "has_table_privilege(session_user, 'public.work_queue', 'UPDATE'), "
                    "has_table_privilege(session_user, 'public.run_owner', 'INSERT')"
                ).fetchone()
                == expected_privileges
            )

    pool = create_pool(
        api_dsn,
        min_size=1,
        max_size=1,
        configure=runtime_pool_configure("tracebed_api"),
    )
    try:
        probe_runtime_prepublication_readiness(pool, expected_role="tracebed_api")
        with pytest.raises(ConfigError):
            probe_runtime_readiness(pool, expected_role="tracebed_api")
        _open_authority_admission(dedicated_0011_dsn)
        probe_runtime_readiness(pool, expected_role="tracebed_api")
        with scoped(pool, ProjectId(uuid4())) as connection:
            assert connection.execute(
                "SELECT NULLIF(current_setting('tracebed.project_id', true), '') IS NOT NULL"
            ).fetchone() == (True,)
        with pool.connection() as connection:
            assert connection.execute(
                "SELECT NULLIF(current_setting('tracebed.project_id', true), '') IS NULL"
            ).fetchone() == (True,)
    finally:
        pool.close()

    with psycopg.connect(worker_dsn) as worker, pytest.raises(ConfigError):
        assert_runtime_connection(worker, expected_role="tracebed_api")

    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("GRANT tracebed_worker_group TO tracebed_api")
    try:
        with psycopg.connect(api_dsn) as api, pytest.raises(psycopg.errors.InsufficientPrivilege):
            api.execute("SELECT public.tracebed_runtime_readiness()")
    finally:
        with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
            owner.execute("REVOKE tracebed_worker_group FROM tracebed_api")


def test_api_role_rechecks_and_writes_without_registry_update_privileges(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The c12 API uses narrow definer paths, not registry UPDATE or raw DML."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)

    project_id = uuid4()
    data_principal, feedback_principal = uuid4(), uuid4()
    data_agent, feedback_agent = uuid4(), uuid4()
    data_grant, feedback_grant = uuid4(), uuid4()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute(
            "INSERT INTO public.project (project_id, name, status) VALUES (%s, %s, 'active')",
            (project_id, f"api-recheck-{project_id.hex}"),
        )
        for principal_id, label in ((data_principal, "data"), (feedback_principal, "feedback")):
            owner.execute(
                "INSERT INTO public.principal (principal_id, kind, external_ref) VALUES (%s, 'oidc_sub', %s)",
                (principal_id, f"api-recheck-{label}-{principal_id.hex}"),
            )
        for agent_id, principal_id, label in (
            (data_agent, data_principal, "data"),
            (feedback_agent, feedback_principal, "feedback"),
        ):
            owner.execute(
                "INSERT INTO public.agent_type (agent_type_id, project_id, name) VALUES (%s, %s, %s)",
                (agent_id, project_id, f"api-recheck-{label}-{agent_id.hex}"),
            )
            owner.execute(
                "INSERT INTO public.agent_registration (principal_id, project_id, agent_type_id) VALUES (%s, %s, %s)",
                (principal_id, project_id, agent_id),
            )
        owner.execute(
            "INSERT INTO public.principal_grant (grant_id, principal_id, project_id, role) "
            "VALUES (%s, %s, %s, 'data')",
            (data_grant, data_principal, project_id),
        )
        owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) VALUES (%s, %s, 'admin')",
            (data_principal, project_id),
        )
        owner.execute(
            "INSERT INTO public.principal_grant (grant_id, principal_id, project_id, role, feedback_source) "
            "VALUES (%s, %s, %s, 'feedback', 'verdict')",
            (feedback_grant, feedback_principal, project_id),
        )
        ensure_schema_current(owner)
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )
        owner.execute("SELECT public.tracebed_open_authority_admission()")
    _open_authority_admission(dedicated_0011_dsn)

    data_access = AccessContext(
        project_id=ProjectId(project_id),
        agent_type_id=AgentTypeId(data_agent),
        principal_id=PrincipalId(data_principal),
        grants=(GrantBinding(data_grant, ProjectRole.DATA),),
    )
    feedback_access = AccessContext(
        project_id=ProjectId(project_id),
        agent_type_id=AgentTypeId(feedback_agent),
        principal_id=PrincipalId(feedback_principal),
        grants=(GrantBinding(feedback_grant, ProjectRole.FEEDBACK, FeedbackSource.VERDICT),),
    )
    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    api_pool = ConnectionPool(api_dsn, min_size=1, max_size=4, open=True)
    activity_pool = create_activity_pool(
        api_dsn, connect_timeout_s=2, checkout_timeout_s=2.0, min_size=1, max_size=2
    )
    try:
        gate = ActivityGate(activity_pool)
        queue = AuthorizedWorkQueue(api_pool, FakeClock(), QueueConfig(), activity=gate)
        run_a, run_b, run_retrieve = RunId(uuid4()), RunId(uuid4()), RunId(uuid4())

        # One API-role transaction admits the two trace runs.  This exercises
        # the grant recheck, immutable owner bind, capacity locks, and v1 insert.
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    run_a,
                    TraceQueuePayload(
                        seq=0,
                        event={"type": "run_start", "ts": "2026-01-01T00:00:00Z", "payload": {}},
                    ),
                ),
                AuthorizedQueueWrite(
                    TOPIC_TRACE_EVENT,
                    run_b,
                    TraceQueuePayload(
                        seq=0,
                        event={"type": "run_start", "ts": "2026-01-01T00:00:00Z", "payload": {}},
                    ),
                ),
            ),
        )
        assert queue.enqueue_many_authorized(
            feedback_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_OUTCOME_EVENT,
                    run_a,
                    OutcomeQueuePayload(
                        event_id=uuid4(), outcome="positive", payload={"kind": "verified"}
                    ),
                ),
            ),
        )
        assert queue.enqueue_many_authorized(
            data_access,
            (
                AuthorizedQueueWrite(
                    TOPIC_MEMORY_PROPOSAL,
                    run_a,
                    ProposalQueuePayload(
                        proposal={
                            "mem_type": "lesson",
                            "content": "bounded",
                            "claimed_scope": "agent_type",
                        }
                    ),
                ),
            ),
        )
        retrieval = AuthorizedRetrievalOpener(api_pool, activity=gate)
        opened = retrieval.open(data_access, run_retrieve)
        assert (
            opened.run_id == run_retrieve and opened.owner_principal_id == data_access.principal_id
        )
        invalidation = AuthorizedInvalidationWriter(api_pool, FakeClock(), activity=gate)
        assert invalidation.insert(data_access, "source_changed", {"scope": "project"})

        # An untrusted snapshot cannot invoke a different grant through the
        # definer function; the Python boundary remains deliberately opaque.
        forged = AccessContext(
            project_id=data_access.project_id,
            agent_type_id=data_access.agent_type_id,
            principal_id=data_access.principal_id,
            grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
        )
        with pytest.raises(AuthorizationDenied):
            queue.enqueue_many_authorized(
                forged,
                (
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        RunId(uuid4()),
                        TraceQueuePayload(
                            seq=0,
                            event={
                                "type": "run_start",
                                "ts": "2026-01-01T00:00:00Z",
                                "payload": {},
                            },
                        ),
                    ),
                ),
            )
    finally:
        api_pool.close()
        activity_pool.close()

    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT has_function_privilege('tracebed_api', "
            "'public.tracebed_require_active_grant(uuid,uuid,uuid,uuid,text,text)'::regprocedure, 'EXECUTE'), "
            "has_function_privilege('tracebed_worker', "
            "'public.tracebed_require_active_grant(uuid,uuid,uuid,uuid,text,text)'::regprocedure, 'EXECUTE'), "
            "has_table_privilege('tracebed_api', 'public.project', 'UPDATE'), "
            "has_table_privilege('tracebed_api', 'public.principal_grant', 'UPDATE'), "
            "has_table_privilege('tracebed_api', 'public.run_owner', 'UPDATE'), "
            "has_table_privilege('tracebed_api', 'public.run_owner', 'DELETE')"
        ).fetchone() == (True, False, False, False, False, False)

    with psycopg.connect(api_dsn) as api:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            api.execute(
                "UPDATE public.project SET status = 'suspended' WHERE project_id = %s",
                (project_id,),
            )
        api.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            api.execute("DELETE FROM public.run_owner WHERE project_id = %s", (project_id,))
        api.rollback()
    with psycopg.connect(
        _role_dsn(dedicated_0011_dsn, "tracebed_worker", "worker-password")
    ) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute(
                "SELECT * FROM public.tracebed_require_active_grant(%s, %s, %s, %s, 'data', NULL)",
                (project_id, data_principal, data_agent, data_grant),
            )
        worker.rollback()


def test_revoke_suspend_and_delete_races_wait_then_refuse_api_writes(
    dedicated_0011_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each c12 registry race linearizes at the definer lock before a durable write."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    identities: list[tuple[ProjectId, AgentTypeId, PrincipalId, GrantBinding]] = []
    with psycopg.connect(dedicated_0011_dsn) as owner:
        for label in ("revoke", "suspend", "delete"):
            project_id, principal_id, agent_type_id, grant_id = uuid4(), uuid4(), uuid4(), uuid4()
            owner.execute(
                "INSERT INTO public.project (project_id, name, status) VALUES (%s, %s, 'active')",
                (project_id, f"api-race-{label}-{project_id.hex}"),
            )
            owner.execute(
                "INSERT INTO public.principal (principal_id, kind, external_ref) VALUES (%s, 'oidc_sub', %s)",
                (principal_id, f"api-race-{label}-{principal_id.hex}"),
            )
            owner.execute(
                "INSERT INTO public.agent_type (agent_type_id, project_id, name) VALUES (%s, %s, %s)",
                (agent_type_id, project_id, f"api-race-{label}-{agent_type_id.hex}"),
            )
            owner.execute(
                "INSERT INTO public.agent_registration (principal_id, project_id, agent_type_id) VALUES (%s, %s, %s)",
                (principal_id, project_id, agent_type_id),
            )
            owner.execute(
                "INSERT INTO public.principal_grant (grant_id, principal_id, project_id, role) "
                "VALUES (%s, %s, %s, 'data')",
                (grant_id, principal_id, project_id),
            )
            owner.execute(
                "INSERT INTO public.principal_grant (principal_id, project_id, role) VALUES (%s, %s, 'admin')",
                (principal_id, project_id),
            )
            identities.append(
                (
                    ProjectId(project_id),
                    AgentTypeId(agent_type_id),
                    PrincipalId(principal_id),
                    GrantBinding(grant_id, ProjectRole.DATA),
                )
            )
        ensure_schema_current(owner)
        owner.commit()

    assert apply_migrations(
        _attested_dsn(dedicated_0011_dsn), through="0011_authority_cutover"
    ) == ["0011_authority_cutover"]
    # The API producer/read/invalidator surfaces are deliberately c12-only:
    # raw c11 queue DML is not a compatibility fallback after E2 is released.
    # Establish the same closed/drained, explicitly activated c12 runtime used
    # by the E2 integration proof before racing its active-grant rechecks.
    monkeypatch.setattr(bootstrap, "apply_migrations", lambda _dsn, **_kwargs: [])
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SELECT public.tracebed_close_authority_admission()")
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0012_erasure_saga"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.erasure_cutover_state SET activated_at = clock_timestamp() WHERE singleton"
        )
        owner.execute("SELECT public.tracebed_open_authority_admission()")
    _open_authority_admission(dedicated_0011_dsn)
    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    api_pool = ConnectionPool(api_dsn, min_size=1, max_size=4, open=True)
    activity_pool = create_activity_pool(
        api_dsn, connect_timeout_s=2, checkout_timeout_s=2.0, min_size=1, max_size=2
    )
    try:
        gate = ActivityGate(activity_pool)
        queue = AuthorizedWorkQueue(api_pool, FakeClock(), QueueConfig(), activity=gate)
        retrieval = AuthorizedRetrievalOpener(api_pool, activity=gate)
        invalidation = AuthorizedInvalidationWriter(api_pool, FakeClock(), activity=gate)
        accesses = [
            AccessContext(project, agent, principal, (grant,))
            for project, agent, principal, grant in identities
        ]

        def _expect_wait_then_denial(
            owner_sql: tuple[str, ...], params: tuple[object, ...], invoke: Callable[[], object]
        ) -> None:
            errors: list[Exception] = []
            started = threading.Event()

            def _run() -> None:
                started.set()
                try:
                    invoke()
                except Exception as exc:  # expected opaque application refusal
                    errors.append(exc)

            with psycopg.connect(dedicated_0011_dsn) as owner:
                for statement in owner_sql:
                    owner.execute(statement, params)
                worker = threading.Thread(target=_run)
                worker.start()
                assert started.wait(timeout=2)
                time.sleep(0.15)
                assert worker.is_alive(), "API recheck did not wait on the registry mutation"
                owner.commit()
            worker.join(timeout=3)
            assert not worker.is_alive()
            assert len(errors) == 1 and type(errors[0]) is AuthorizationDenied

        revoke_access = accesses[0]
        revoke_grant = revoke_access.grant_for(ProjectRole.DATA)
        assert revoke_grant is not None
        _expect_wait_then_denial(
            (
                "UPDATE public.principal_grant SET revoked_at = clock_timestamp() WHERE grant_id = %s",
            ),
            (revoke_grant.grant_id,),
            lambda: queue.enqueue_many_authorized(
                revoke_access,
                (
                    AuthorizedQueueWrite(
                        TOPIC_TRACE_EVENT,
                        RunId(uuid4()),
                        TraceQueuePayload(
                            seq=0,
                            event={
                                "type": "run_start",
                                "ts": "2026-01-01T00:00:00Z",
                                "payload": {},
                            },
                        ),
                    ),
                ),
            ),
        )

        suspend_access = accesses[1]
        _expect_wait_then_denial(
            ("UPDATE public.project SET status = 'suspended' WHERE project_id = %s",),
            (suspend_access.project_id.value,),
            lambda: retrieval.open(suspend_access, RunId(uuid4())),
        )

        delete_access = accesses[2]
        _expect_wait_then_denial(
            (
                "UPDATE public.project SET status = 'deleting' WHERE project_id = %s",
                "UPDATE public.project SET status = 'deleted' WHERE project_id = %s",
            ),
            (delete_access.project_id.value,),
            lambda: invalidation.insert(delete_access, "source_changed", {"scope": "project"}),
        )
    finally:
        api_pool.close()
        activity_pool.close()


def test_admission_close_waits_for_an_admitted_api_transaction_then_fences_new_work(
    dedicated_0011_dsn: str,
) -> None:
    """The owner close is a durable row-lock fence, not a process-stop hint."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    project_id, principal_id, agent_type_id, grant_id = uuid4(), uuid4(), uuid4(), uuid4()
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute(
            "INSERT INTO public.project (project_id, name, status) VALUES (%s, %s, 'active')",
            (project_id, f"admission-fence-{project_id.hex}"),
        )
        owner.execute(
            "INSERT INTO public.principal (principal_id, kind, external_ref) VALUES (%s, 'oidc_sub', %s)",
            (principal_id, f"admission-fence-{principal_id.hex}"),
        )
        owner.execute(
            "INSERT INTO public.agent_type (agent_type_id, project_id, name) VALUES (%s, %s, %s)",
            (agent_type_id, project_id, f"admission-fence-{agent_type_id.hex}"),
        )
        owner.execute(
            "INSERT INTO public.agent_registration (principal_id, project_id, agent_type_id) VALUES (%s, %s, %s)",
            (principal_id, project_id, agent_type_id),
        )
        owner.execute(
            "INSERT INTO public.principal_grant (grant_id, principal_id, project_id, role) "
            "VALUES (%s, %s, %s, 'data')",
            (grant_id, principal_id, project_id),
        )
        owner.execute(
            "INSERT INTO public.principal_grant (principal_id, project_id, role) VALUES (%s, %s, 'admin')",
            (principal_id, project_id),
        )
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )

    api_dsn = _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
    require = "SELECT * FROM public.tracebed_require_active_grant(%s, %s, %s, %s, %s, %s)"
    arguments = (project_id, principal_id, agent_type_id, grant_id, "data", None)
    # Bootstrap activation is deliberately not publication: closed admission
    # rejects even a syntactically valid direct API recheck.
    with psycopg.connect(api_dsn) as closed_api:
        closed_api.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            closed_api.execute(require, arguments)
    _open_authority_admission(dedicated_0011_dsn)

    api = psycopg.connect(api_dsn)
    api.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
    assert api.execute(require, arguments).fetchone() == (grant_id, "data", None)
    close_errors: list[Exception] = []
    close_started = threading.Event()

    def close_admission() -> None:
        close_started.set()
        try:
            with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
                owner.execute("SELECT public.tracebed_close_authority_admission()")
        except Exception as error:  # assertion below reports the exact failed close path
            close_errors.append(error)

    closer = threading.Thread(target=close_admission)
    closer.start()
    assert close_started.wait(timeout=2)
    time.sleep(0.15)
    assert closer.is_alive(), "owner close did not wait for the admitted API transaction"
    # Closing the held backend ends its transaction and removes the API
    # session, allowing the owner routine to obtain UPDATE and publish closed.
    api.close()
    closer.join(timeout=3)
    assert not closer.is_alive()
    assert close_errors == []
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT admissions_open FROM public.authority_admission_state WHERE singleton"
        ).fetchone() == (False,)
    with psycopg.connect(api_dsn) as fenced_api:
        fenced_api.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            fenced_api.execute(require, arguments)


def test_cutover_requires_an_already_committed_legacy_nologin_quarantine(
    dedicated_0011_dsn: str,
) -> None:
    """0011 itself never races a legacy LOGIN by disabling it in-transaction."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("ALTER ROLE tracebed_app LOGIN")

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'tracebed_app'"
        ).fetchone() == (True,)


def test_bootstrap_requires_explicit_ingress_attestation_before_legacy_quarantine(
    dedicated_0011_dsn: str,
) -> None:
    """Latest bootstrap never silently disables a pre-existing LOGIN role."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("ALTER ROLE tracebed_app LOGIN")

    with pytest.raises(ConfigError, match="TB_0011_INGRESS_QUARANTINED"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
        )
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'tracebed_app'"
        ).fetchone() == (True,)

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"


def test_nonexpired_credential_probe_refuses_cleanup_without_termination(
    dedicated_0011_dsn: str,
) -> None:
    """Stale cleanup never treats a still-live bootstrap nonce as disposable."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    owner_dsn = _attested_dsn(dedicated_0011_dsn)
    assert apply_migrations(owner_dsn) == ["0011_authority_cutover"]
    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        probe_role, _ = bootstrap._prepare_credential_probe(
            owner, owner_dsn=owner_dsn, password="probe-password"
        )
        with pytest.raises(RuntimeError, match="credential probe has unsafe state"):
            bootstrap._cleanup_stale_credential_probes(owner)
        assert owner.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", (probe_role,)
        ).fetchone() == (True,)
        bootstrap._drop_credential_probe(owner, probe_role)


def test_expired_credential_probe_is_terminated_and_dropped_in_one_cleanup(
    dedicated_0011_dsn: str,
) -> None:
    """One stale sweep consumes termination truth and a fresh PG18 stats read."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    owner_dsn = _attested_dsn(dedicated_0011_dsn)
    assert apply_migrations(owner_dsn) == ["0011_authority_cutover"]
    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        probe_role, _ = bootstrap._prepare_credential_probe(
            owner, owner_dsn=owner_dsn, password="probe-password"
        )
        with psycopg.connect(_role_dsn(owner_dsn, probe_role, "probe-password")) as held:
            owner.execute(
                sql.SQL("ALTER ROLE {} VALID UNTIL 'epoch'").format(sql.Identifier(probe_role))
            )
            bootstrap._cleanup_stale_credential_probes(owner)
            with pytest.raises(psycopg.OperationalError):
                held.execute("SELECT 1")

    # This independent connection has no transaction-local statistics snapshot
    # from the cleanup transaction: a single sweep both evicted and dropped.
    with psycopg.connect(owner_dsn) as observer:
        assert observer.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (probe_role,)
        ).fetchone() == (0,)
        assert observer.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)", (probe_role,)
        ).fetchone() == (False,)


@pytest.mark.parametrize("failure", ("false", "error"))
def test_stale_probe_termination_failure_retains_batch_and_skips_later_candidates(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """A false/error termination result rolls back catalog cleanup before candidate two."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    owner_dsn = _attested_dsn(dedicated_0011_dsn)
    assert apply_migrations(owner_dsn) == ["0011_authority_cutover"]
    nonce_values = iter(("0" * 32, "f" * 32))
    monkeypatch.setattr(bootstrap, "uuid4", lambda: SimpleNamespace(hex=next(nonce_values)))

    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        first_role, _ = bootstrap._prepare_credential_probe(
            owner, owner_dsn=owner_dsn, password="first-probe-password"
        )
        second_role, _ = bootstrap._prepare_credential_probe(
            owner, owner_dsn=owner_dsn, password="second-probe-password"
        )
        with psycopg.connect(_role_dsn(owner_dsn, first_role, "first-probe-password")) as held:
            for probe_role in (first_role, second_role):
                owner.execute(
                    sql.SQL("ALTER ROLE {} VALID UNTIL 'epoch'").format(sql.Identifier(probe_role))
                )
            attempted: list[str] = []

            def fail_termination(
                _cursor: psycopg.Cursor[Any], probe_role: str
            ) -> list[tuple[Any, ...]]:
                attempted.append(probe_role)
                if failure == "false":
                    return [(False,)]
                raise psycopg.OperationalError("injected stale-probe termination error")

            original = bootstrap._credential_probe_termination_results
            monkeypatch.setattr(
                bootstrap, "_credential_probe_termination_results", fail_termination
            )
            try:
                expected = RuntimeError if failure == "false" else psycopg.OperationalError
                with pytest.raises(expected):
                    bootstrap._cleanup_stale_credential_probes(owner)
            finally:
                monkeypatch.setattr(bootstrap, "_credential_probe_termination_results", original)

            assert attempted == [first_role]
            assert held.execute("SELECT 1").fetchone() == (1,)
            with psycopg.connect(owner_dsn) as observer:
                assert observer.execute(
                    "SELECT rolname FROM pg_roles WHERE rolname IN (%s, %s) ORDER BY rolname",
                    (first_role, second_role),
                ).fetchall() == [(first_role,), (second_role,)]
        bootstrap._drop_credential_probe(owner, first_role)
        bootstrap._drop_credential_probe(owner, second_role)


def test_already_nologin_legacy_app_session_is_evicted_before_cutover(
    dedicated_0011_dsn: str,
) -> None:
    """NOLOGIN is not mistaken for proof that an older session is gone."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("ALTER ROLE tracebed_app LOGIN")
    legacy = psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_app", "legacy-password"))
    try:
        with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
            owner.execute("ALTER ROLE tracebed_app NOLOGIN")
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
        with pytest.raises(psycopg.OperationalError):
            legacy.execute("SELECT 1")
        assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    finally:
        legacy.close()


def test_active_bootstrap_retry_is_catalog_read_only(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Active credential rechecks must not rerun yoyo, repair, or nonce cleanup."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        before = owner.execute(
            "SELECT activated_at, "
            "(SELECT rolpassword FROM pg_authid WHERE rolname = 'tracebed_api'), "
            "(SELECT rolpassword FROM pg_authid WHERE rolname = 'tracebed_worker'), "
            "(SELECT count(*) FROM public.authority_acl_epoch) "
            "FROM public.authority_cutover_state WHERE singleton"
        ).fetchone()

    def unexpected_write(*_: object, **__: object) -> None:
        raise AssertionError("active retry attempted a write-capable bootstrap phase")

    monkeypatch.setattr(bootstrap, "apply_migrations", unexpected_write)
    monkeypatch.setattr(bootstrap, "ensure_schema_current", unexpected_write)
    monkeypatch.setattr(bootstrap, "_cleanup_stale_credential_probes", unexpected_write)
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        after = owner.execute(
            "SELECT activated_at, "
            "(SELECT rolpassword FROM pg_authid WHERE rolname = 'tracebed_api'), "
            "(SELECT rolpassword FROM pg_authid WHERE rolname = 'tracebed_worker'), "
            "(SELECT count(*) FROM public.authority_acl_epoch) "
            "FROM public.authority_cutover_state WHERE singleton"
        ).fetchone()
    assert after == before


def test_schema_epoch_accepts_valid_project_partitions_and_refuses_leaf_rls_drift(
    dedicated_0011_dsn: str,
) -> None:
    """The epoch is stable across normal provisioning but fences unsafe leaves."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"


def test_schema_epoch_refuses_project_leaf_rls_drift_before_cutover(
    dedicated_0011_dsn: str,
) -> None:
    """A concrete attached leaf cannot weaken FORCE RLS before 0011."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf = owner.execute(
            "SELECT leaf.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid "
            "WHERE inheritance.inhparent = 'public.memory_item'::regclass"
        ).fetchone()
        assert leaf is not None and len(leaf) == 1 and isinstance(leaf[0], str)
        owner.execute(
            sql.SQL("ALTER TABLE public.{} NO FORCE ROW LEVEL SECURITY").format(
                sql.Identifier(leaf[0])
            )
        )
        owner.commit()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_schema_epoch_refuses_project_leaf_policy_drift_before_cutover(
    dedicated_0011_dsn: str,
) -> None:
    """A cloned leaf policy cannot be weakened while retaining FORCE RLS."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf = owner.execute(
            "SELECT leaf.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid "
            "WHERE inheritance.inhparent = 'public.memory_item'::regclass"
        ).fetchone()
        assert leaf is not None and len(leaf) == 1 and isinstance(leaf[0], str)
        policy_name = f"{leaf[0]}_isolation"
        owner.execute(
            sql.SQL("DROP POLICY {} ON public.{}").format(
                sql.Identifier(policy_name), sql.Identifier(leaf[0])
            )
        )
        owner.execute(
            sql.SQL("CREATE POLICY {} ON public.{} USING (true)").format(
                sql.Identifier(policy_name), sql.Identifier(leaf[0])
            )
        )
        owner.commit()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_schema_epoch_refuses_project_leaf_trigger_drift_before_cutover(
    dedicated_0011_dsn: str,
) -> None:
    """A partition cannot disable the cloned terminal-trace trigger."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        trigger = owner.execute(
            "SELECT leaf.relname, child_trigger.tgname "
            "FROM pg_inherits AS inheritance "
            "JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid "
            "JOIN pg_trigger AS child_trigger ON child_trigger.tgrelid = leaf.oid "
            "WHERE inheritance.inhparent = 'public.trace_index'::regclass "
            "AND NOT child_trigger.tgisinternal"
        ).fetchone()
        assert (
            trigger is not None
            and len(trigger) == 2
            and isinstance(trigger[0], str)
            and isinstance(trigger[1], str)
        )
        owner.execute(
            sql.SQL("ALTER TABLE public.{} DISABLE TRIGGER {}").format(
                sql.Identifier(trigger[0]), sql.Identifier(trigger[1])
            )
        )
        owner.commit()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_schema_epoch_refuses_project_leaf_constraint_drift_before_cutover(
    dedicated_0011_dsn: str,
) -> None:
    """A local partition CHECK is not allowed to silently redefine authority data."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf = owner.execute(
            "SELECT leaf.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid "
            "WHERE inheritance.inhparent = 'public.memory_item'::regclass"
        ).fetchone()
        assert leaf is not None and len(leaf) == 1 and isinstance(leaf[0], str)
        owner.execute(
            sql.SQL("ALTER TABLE public.{} ADD CONSTRAINT {} CHECK (true)").format(
                sql.Identifier(leaf[0]), sql.Identifier(f"{leaf[0]}_unexpected")
            )
        )
        owner.commit()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_schema_epoch_refuses_missing_active_project_leaf_before_cutover(
    dedicated_0011_dsn: str,
) -> None:
    """Every active project must remain attached to every authority parent."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf = owner.execute(
            "SELECT leaf.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid "
            "WHERE inheritance.inhparent = 'public.memory_item'::regclass"
        ).fetchone()
        assert leaf is not None and len(leaf) == 1 and isinstance(leaf[0], str)
        owner.execute(
            sql.SQL("ALTER TABLE public.memory_item DETACH PARTITION public.{}").format(
                sql.Identifier(leaf[0])
            )
        )
        owner.commit()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_schema_epoch_refuses_project_leaf_index_drift_before_cutover(
    dedicated_0011_dsn: str,
) -> None:
    """A canonical per-project retrieval/filter index cannot disappear before cutover."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf = owner.execute(
            "SELECT leaf.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid "
            "WHERE inheritance.inhparent = 'public.memory_item'::regclass"
        ).fetchone()
        assert leaf is not None and len(leaf) == 1 and isinstance(leaf[0], str)
        owner.execute(sql.SQL("DROP INDEX public.{}").format(sql.Identifier(f"{leaf[0]}_status")))
        owner.commit()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_yoyo_and_authority_ddl_ignore_an_owner_named_schema(
    dedicated_0011_dsn: str,
) -> None:
    """A hostile owner schema is neither selected nor silently tolerated."""

    hostile_dsn = f"{dedicated_0011_dsn}?options=-c%20search_path%3Dtracebed_owner%2Cpublic"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("CREATE SCHEMA tracebed_owner")
        owner.commit()

    # The trusted migration URL parser now refuses caller-controlled libpq
    # options before yoyo creates even its bookkeeping state.  That is stronger
    # than accepting the hostile search path and relying on later SQL fences.
    with pytest.raises(ValueError, match="requires a PostgreSQL URL DSN"):
        apply_migrations(hostile_dsn)
    assert current_revision(dedicated_0011_dsn) == []

    with psycopg.connect(dedicated_0011_dsn) as owner:
        hostile_objects = owner.execute(
            "SELECT count(*) FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'tracebed_owner'"
        ).fetchone()
        catalog_objects = owner.execute(
            "SELECT count(*) FROM pg_proc AS routine "
            "JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace "
            "WHERE namespace.nspname = 'pg_catalog' "
            "AND routine.proname IN ("
            "'project_enforce_lifecycle', 'authority_acl_security_assert', "
            "'authority_schema_security_assert'"
            ")"
        ).fetchone()
        yoyo_lock = owner.execute("SELECT to_regclass('public.yoyo_lock')").fetchone()
        assert hostile_objects == (0,)
        assert catalog_objects == (0,)
        assert yoyo_lock is not None and isinstance(yoyo_lock[0], str)
        owner.execute("DROP SCHEMA tracebed_owner")
        owner.commit()


def test_rollback_quarantine_blocks_the_activity_marker(dedicated_0011_dsn: str) -> None:
    """The receipt-side fence closes activity before rollback mutates DDL."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute(
            "UPDATE public.authority_cutover_state "
            "SET rollback_quarantined_at = clock_timestamp() WHERE singleton"
        )
        owner.commit()
    with (
        psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")) as api,
        pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState),
    ):
        _insert_authority_v1_trace_event(api, project_id)


def test_digest_helper_tamper_blocks_activation_without_publishing_logins(
    dedicated_0011_dsn: str,
) -> None:
    """Bootstrap authenticates every digest-chain helper before publication."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            """
            CREATE OR REPLACE FUNCTION public.authority_acl_frame(value bytea)
            RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
            SET search_path = pg_catalog
            AS $$ SELECT value $$
            """
        )
    with pytest.raises(RuntimeError, match="digest helper manifest"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(NOT role.rolcanlogin), bool_and(auth.rolpassword IS NULL) "
            "FROM public.authority_cutover_state AS receipt CROSS JOIN pg_roles AS role "
            "JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True)


def test_digest_helper_tamper_blocks_foundation_rollback_before_mutation(
    dedicated_0011_dsn: str,
) -> None:
    """0010 rollback authenticates framing helpers before reading its receipt."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            """
            CREATE OR REPLACE FUNCTION public.authority_acl_frame(value bytea)
            RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
            SET search_path = pg_catalog
            AS $$ SELECT value $$
            """
        )
    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="unauthenticated digest helper"
    ):
        rollback_migrations(dedicated_0011_dsn)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute("SELECT to_regclass('public.authority_acl_epoch')").fetchone() == (
            "authority_acl_epoch",
        )


def test_digest_helper_tamper_blocks_cutover_rollback_before_mutation(
    dedicated_0011_dsn: str,
) -> None:
    """0011 rollback repeats the complete helper fence independently."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            """
            CREATE OR REPLACE FUNCTION public.authority_acl_frame(value bytea)
            RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
            SET search_path = pg_catalog
            AS $$ SELECT value $$
            """
        )
    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="unauthenticated digest helper"
    ):
        rollback_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute("SELECT to_regclass('public.authority_cutover_state')").fetchone() == (
            "authority_cutover_state",
        )


def test_fifth_database_and_protected_role_setting_refuse_without_mutation(
    dedicated_0011_dsn: str,
) -> None:
    """Inventory and role-GUC evidence are checked before 0011 mutates ACLs."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute('CREATE DATABASE "tracebed_0011_extra"')
        before_extra_acl = owner.execute(
            "SELECT datacl FROM pg_database WHERE datname = 'tracebed_0011_extra'"
        ).fetchone()
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        assert (
            owner.execute(
                "SELECT datacl FROM pg_database WHERE datname = 'tracebed_0011_extra'"
            ).fetchone()
            == before_extra_acl
        )
        owner.execute('DROP DATABASE "tracebed_0011_extra"')
        owner.execute("ALTER ROLE tracebed_app SET search_path = 'pg_catalog'")
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rolconfig IS NOT NULL FROM pg_roles WHERE rolname = 'tracebed_app'"
        ).fetchone() == (True,)


def test_unexpected_legacy_acl_refuses_without_erasing_evidence(
    dedicated_0011_dsn: str,
) -> None:
    """0011 subtracts only staged legacy grants before checking residual ACLs."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("CREATE SCHEMA cutover_attacker")
        owner.execute("CREATE TABLE cutover_attacker.keep_table (id integer)")
        owner.execute(
            "CREATE FUNCTION cutover_attacker.keep_function() RETURNS integer "
            "LANGUAGE sql AS 'SELECT 1'"
        )
        owner.execute("GRANT USAGE ON SCHEMA cutover_attacker TO tracebed_app")
        owner.execute("GRANT SELECT ON cutover_attacker.keep_table TO tracebed_app")
        owner.execute("GRANT EXECUTE ON FUNCTION cutover_attacker.keep_function() TO tracebed_app")
        attacker_before = owner.execute(
            "SELECT namespace.nspacl, relation.relacl, routine.proacl "
            "FROM pg_namespace AS namespace "
            "JOIN pg_class AS relation ON relation.relnamespace = namespace.oid "
            "JOIN pg_proc AS routine ON routine.pronamespace = namespace.oid "
            "WHERE namespace.nspname = 'cutover_attacker' "
            "AND relation.relname = 'keep_table' AND routine.proname = 'keep_function'"
        ).fetchone()
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        assert (
            owner.execute(
                "SELECT namespace.nspacl, relation.relacl, routine.proacl "
                "FROM pg_namespace AS namespace "
                "JOIN pg_class AS relation ON relation.relnamespace = namespace.oid "
                "JOIN pg_proc AS routine ON routine.pronamespace = namespace.oid "
                "WHERE namespace.nspname = 'cutover_attacker' "
                "AND relation.relname = 'keep_table' AND routine.proname = 'keep_function'"
            ).fetchone()
            == attacker_before
        )
        owner.execute(
            "REVOKE EXECUTE ON FUNCTION cutover_attacker.keep_function() FROM tracebed_app"
        )
        owner.execute("REVOKE SELECT ON cutover_attacker.keep_table FROM tracebed_app")
        owner.execute("REVOKE USAGE ON SCHEMA cutover_attacker FROM tracebed_app")
        owner.execute("DROP SCHEMA cutover_attacker CASCADE")
        owner.execute("GRANT CONNECT ON DATABASE postgres TO tracebed_app")
        postgres_before = owner.execute(
            "SELECT datacl FROM pg_database WHERE datname = 'postgres'"
        ).fetchone()
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        assert (
            owner.execute("SELECT datacl FROM pg_database WHERE datname = 'postgres'").fetchone()
            == postgres_before
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "REVOKE SELECT ON public.project FROM tracebed_app",
        "GRANT SELECT ON public.project TO tracebed_app WITH GRANT OPTION",
        "CREATE SEQUENCE public.acl_profile_extra_sequence; "
        "GRANT USAGE ON SEQUENCE public.acl_profile_extra_sequence TO tracebed_app",
        "GRANT USAGE ON TYPE public.halfvec TO tracebed_app",
        "GRANT DELETE ON public.yoyo_lock TO tracebed_app WITH GRANT OPTION",
    ],
    ids=("missing", "grant-option", "sequence", "extension-type", "yoyo-grant-option"),
)
def test_exact_0010_acl_profile_refuses_missing_and_extra_acl_tuples(
    dedicated_0011_dsn: str, mutation: str
) -> None:
    """The epoch comparison is equality: missing, extra, and delegated fail."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        for statement in mutation.split("; "):
            owner.execute(statement)

    # Delegated tuples fail even earlier than the digest comparison; ordinary
    # missing/extra tuples reach the exact epoch-profile fence.
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_partition_acl_digest_requires_the_deterministic_project_leaf_name(
    dedicated_0011_dsn: str,
) -> None:
    """A LIST bound alone cannot normalize a renamed project partition."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf = owner.execute(
            "SELECT child.oid::regclass::text "
            "FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.oid = 'public.memory_item'::regclass"
        ).fetchone()
        assert leaf is not None and isinstance(leaf[0], str)
        owner.execute(
            sql.SQL("ALTER TABLE {} RENAME TO {}").format(
                sql.Identifier(*leaf[0].split(".")), sql.Identifier("renamed_acl_leaf")
            )
        )
        owner.commit()
        for assertion in (
            "public.authority_acl_security_assert('genuine_0010')",
            "public.authority_schema_security_assert('genuine_0010')",
        ):
            with pytest.raises(
                psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
            ):
                owner.execute(f"SELECT {assertion}")
            owner.rollback()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


@pytest.mark.parametrize(
    "grant_sql",
    (
        "GRANT SELECT ON public.project TO tracebed_epoch_intruder",
        "GRANT USAGE ON SCHEMA tokenizer_catalog TO tracebed_epoch_intruder",
        "GRANT EXECUTE ON FUNCTION public.subject_digests_are_valid(bytea[]) TO tracebed_epoch_intruder",
        "GRANT USAGE ON TYPE public.halfvec TO tracebed_epoch_intruder",
        "GRANT SET ON PARAMETER work_mem TO tracebed_epoch_intruder",
    ),
    ids=("relation", "schema", "routine", "type", "parameter"),
)
def test_acl_profile_enumerates_noncanonical_grantees_in_every_live_acl_class(
    dedicated_0011_dsn: str, grant_sql: str
) -> None:
    """A grant to an unrelated role is receipt-visible before hardening can erase it."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("CREATE ROLE tracebed_epoch_intruder NOLOGIN")
        baseline = owner.execute(
            "SELECT public.authority_acl_security_assert('genuine_0010')"
        ).fetchone()
        assert baseline is not None
        owner.execute(grant_sql)
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_acl_security_assert('genuine_0010')")

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
    ):
        apply_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


@pytest.mark.parametrize(
    "poison_sql",
    (
        "GRANT SELECT ON public.project TO tracebed_epoch_intruder",
        "ALTER TABLE public.project ADD COLUMN epoch_poison integer",
        "CREATE TABLE public.epoch_poison (id integer)",
        "GRANT DELETE ON public.trace_index TO tracebed_app",
        "GRANT SELECT ON public.principal TO PUBLIC",
        "ALTER TABLE public.principal ADD COLUMN epoch_poison integer",
        "REVOKE SELECT ON public.trace_index FROM tracebed_app",
    ),
    ids=(
        "foreign-grantee",
        "project-column",
        "public-relation",
        "app-terminal-delete",
        "public-principal-select",
        "principal-column",
        "missing-app-select",
    ),
)
def test_epoch_zero_refuses_a_poisoned_pre_0010_baseline(
    dedicated_0011_dsn: str, poison_sql: str
) -> None:
    """0010 never records arbitrary 0009 ACL/schema state as a genuine receipt."""

    _apply_through_0009(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        if "tracebed_epoch_intruder" in poison_sql:
            owner.execute("CREATE ROLE tracebed_epoch_intruder NOLOGIN")
        owner.execute(poison_sql)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="noncanonical pre-0010"):
        apply_migrations(dedicated_0011_dsn)
    assert current_revision(dedicated_0011_dsn)[0] == "0009_trace_index_terminal_freeze"


def test_cutover_acl_profile_covers_all_dedicated_databases(
    dedicated_0011_dsn: str,
) -> None:
    """PUBLIC CONNECT on postgres/template databases is receipt-visible too."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("GRANT CONNECT ON DATABASE postgres TO PUBLIC")
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_acl_security_assert('cutover_0011')")


def test_checked_in_acl_profile_fixture_matches_clean_reference_transitions(
    dedicated_0011_dsn: str,
) -> None:
    """A disposable reference proves every static profile's generated provenance.

    This is intentionally a byte-for-byte tuple comparison rather than merely
    calling the assertion functions: it proves the literal 0010 fixture is
    the exact normalized output of clean ``genuine -> cutover -> hardened ->
    cutover`` transitions and cannot be hand-edited unnoticed.
    """

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _assert_profile_fixture_matches_live_reference(owner, "genuine_0010")

    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _assert_profile_fixture_matches_live_reference(owner, "cutover_0011")

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    assert rollback_migrations(attested) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _assert_profile_fixture_matches_live_reference(owner, "hardened_0010")

    assert apply_migrations(attested) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _assert_profile_fixture_matches_live_reference(owner, "cutover_0011")


def test_checked_in_fixture_is_independently_regenerated_before_profile_acceptance(
    dedicated_0011_dsn: str,
) -> None:
    """The release generator never consults the checked-in profile rows.

    Its private source copies strip the literal fixture and final receipt,
    collect actual normalized tuples first, and seed those generated values
    only to drive the subsequent clean transition.  A changed literal must
    therefore disagree with this independently constructed reference.
    """

    generator = _independent_manifest_generator()
    independently_generated = generator.collect_clean_reference(dedicated_0011_dsn)
    checked_in = _checked_in_profile_rows()
    assert independently_generated == checked_in

    profile, tuple_class, digest = checked_in[0]
    fixture_source = (_ROOT / "migrations" / "0010_authority_foundation.sql").read_text(
        encoding="utf-8"
    )
    literal = (
        f"('{profile}'::public.authority_acl_profile, '{tuple_class}', decode('{digest}', 'hex'))"
    )
    assert literal in fixture_source
    corrupted_fixture = fixture_source.replace(literal, literal.replace(digest, "0" * 64), 1)
    corrupted = _profile_rows_from_source(corrupted_fixture)
    assert len(corrupted) == len(checked_in)
    assert corrupted != checked_in
    # This source-level literal corruption is not fed to the generator.  Its
    # independently collected actual tuples remain the same clean reference.
    assert independently_generated != corrupted


@pytest.mark.parametrize(
    "statements",
    (
        ("CREATE SCHEMA f1_rogue",),
        (
            "CREATE SCHEMA f1_rogue",
            "CREATE TABLE f1_rogue.audit_probe (value integer)",
            "GRANT USAGE ON SCHEMA f1_rogue TO PUBLIC",
            "GRANT SELECT ON f1_rogue.audit_probe TO PUBLIC",
        ),
    ),
    ids=("empty-schema", "schema-and-public-table-grant"),
)
def test_epoch_zero_refuses_every_rogue_non_system_namespace(
    dedicated_0011_dsn: str, statements: tuple[str, ...]
) -> None:
    """An empty or ACL-bearing user schema is part of the canonical baseline."""

    _apply_through_0009(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        for statement in statements:
            owner.execute(statement)

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
    ):
        apply_migrations(dedicated_0011_dsn)
    assert current_revision(dedicated_0011_dsn)[0] == "0009_trace_index_terminal_freeze"


def test_rogue_namespace_refuses_activation_before_split_roles_publish(
    dedicated_0011_dsn: str,
) -> None:
    """Post-cutover namespace drift leaves split roles staged and non-published."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("CREATE SCHEMA f1_rogue")
        owner.execute("CREATE TABLE f1_rogue.audit_probe (value integer)")
        owner.execute("GRANT USAGE ON SCHEMA f1_rogue TO PUBLIC")
        owner.execute("GRANT SELECT ON f1_rogue.audit_probe TO PUBLIC")

    with pytest.raises(RuntimeError, match="authority epoch profile is not current"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )

    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT activated_at IS NULL FROM public.authority_cutover_state WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname IN ('tracebed_api', 'tracebed_worker') "
            "ORDER BY rolname"
        ).fetchall() == [(False,), (False,)]
        # The rogue PUBLIC grant is evidence, not an ACL emitted by the API
        # group.  The group is still staged and has no direct schema grant.
        assert owner.execute(
            "SELECT NOT EXISTS ("
            "  SELECT 1 FROM pg_namespace AS namespace "
            "  CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS privilege "
            "  JOIN pg_roles AS grantee ON grantee.oid = privilege.grantee "
            "  WHERE namespace.nspname = 'f1_rogue' AND grantee.rolname = 'tracebed_api_group'"
            ")"
        ).fetchone() == (True,)


def test_acl_profile_rejects_a_public_view_grant(
    dedicated_0011_dsn: str,
) -> None:
    """A view is an ACL-bearing relation, not an unprofiled escape hatch."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("CREATE VIEW public.authority_acl_view_probe AS SELECT 1 AS value")
        owner.execute("GRANT SELECT ON public.authority_acl_view_probe TO tracebed_app")
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_acl_security_assert('genuine_0010')")


def test_epoch_zero_requires_the_exact_yoyo_lock_topology(dedicated_0011_dsn: str) -> None:
    """The yoyo table is authenticated structurally, not merely by name."""

    _apply_through_0009(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("ALTER TABLE public.yoyo_lock ENABLE ROW LEVEL SECURITY")
    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="noncanonical yoyo lock topology"
    ):
        apply_migrations(dedicated_0011_dsn)
    assert current_revision(dedicated_0011_dsn)[0] == "0009_trace_index_terminal_freeze"


@pytest.mark.parametrize(
    "poison_sql",
    (
        "CREATE TABLE public._yoyo_lock (locked integer PRIMARY KEY)",
        "ALTER TABLE public.yoyo_lock ADD COLUMN intruder integer",
        "ALTER TABLE public.yoyo_lock SET UNLOGGED",
        "ALTER TABLE public.yoyo_lock SET (fillfactor = 70)",
        "ALTER INDEX public.yoyo_lock_pkey SET (fillfactor = 70)",
        "CLUSTER public.yoyo_lock USING yoyo_lock_pkey",
        "CREATE TABLE public.yoyo_lock_shadow () INHERITS (public.yoyo_lock)",
        "GRANT SELECT ON public.yoyo_lock TO PUBLIC",
    ),
    ids=(
        "underscored-homonym",
        "column",
        "unlogged",
        "table-reloptions",
        "index-reloptions",
        "clustered-index",
        "inherits-child",
        "public-acl",
    ),
)
def test_epoch_zero_requires_complete_yoyo_9_lock_provenance(
    dedicated_0011_dsn: str, poison_sql: str
) -> None:
    """Yoyo's one allowable legacy ACL is not a blanket name-based exception."""

    _apply_through_0009(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(poison_sql)
    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState,
        match=r"noncanonical (pre-0010 (schema|ACL) baseline|yoyo lock topology)|underscored yoyo",
    ):
        apply_migrations(dedicated_0011_dsn)
    assert current_revision(dedicated_0011_dsn)[0] == "0009_trace_index_terminal_freeze"


def test_yoyo_lock_post_epoch_index_drift_is_profile_visible(
    dedicated_0011_dsn: str,
) -> None:
    """The one-way cutover repair does not exempt later yoyo topology drift."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("CREATE INDEX yoyo_lock_pid_drift ON public.yoyo_lock (pid)")
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


@pytest.mark.parametrize(
    "poison_sql",
    (
        "ALTER TABLE public.yoyo_lock SET UNLOGGED",
        "ALTER TABLE public.yoyo_lock SET (fillfactor = 70)",
        "ALTER INDEX public.yoyo_lock_pkey SET (fillfactor = 70)",
        "CLUSTER public.yoyo_lock USING yoyo_lock_pkey",
        "CREATE TABLE public.yoyo_lock_shadow () INHERITS (public.yoyo_lock)",
    ),
    ids=("unlogged", "table-reloptions", "index-reloptions", "clustered-index", "inherits-child"),
)
def test_yoyo_lock_post_epoch_topology_drift_is_profile_visible(
    dedicated_0011_dsn: str, poison_sql: str
) -> None:
    """The schema receipt binds yoyo persistence, reloptions, index flags, and inheritance."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute(poison_sql)
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


def test_schema_profile_binds_trigger_update_column_scope(
    dedicated_0011_dsn: str,
) -> None:
    """A parent UPDATE OF trigger cannot silently weaken terminal freeze clones."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.execute(
            "CREATE OR REPLACE TRIGGER trace_index_terminal_immutability_guard "
            "BEFORE UPDATE OF outcome_status OR DELETE ON public.trace_index "
            "FOR EACH ROW EXECUTE FUNCTION public.trace_index_enforce_terminal_immutability()"
        )
        clone_scope = owner.execute(
            "SELECT COALESCE(string_agg(attribute.attname, ',' ORDER BY member.ordinality), '') "
            "FROM pg_trigger AS trigger "
            "JOIN pg_inherits AS inheritance ON inheritance.inhrelid = trigger.tgrelid "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "CROSS JOIN LATERAL unnest(trigger.tgattr::smallint[]) WITH ORDINALITY "
            "  AS member(attnum, ordinality) "
            "JOIN pg_attribute AS attribute "
            "  ON attribute.attrelid = trigger.tgrelid AND attribute.attnum = member.attnum "
            "WHERE parent.oid = 'public.trace_index'::regclass "
            "  AND trigger.tgname = 'trace_index_terminal_immutability_guard'"
        ).fetchone()
        assert clone_scope == ("outcome_status",)
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


def test_schema_and_acl_profiles_reject_nonpartition_inheritance(
    dedicated_0011_dsn: str,
) -> None:
    """Only verified project leaves are dynamic; arbitrary INHERITS edges are drift."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("CREATE TABLE public.work_queue_shadow () INHERITS (public.work_queue)")
        owner.commit()
        for assertion in (
            "public.authority_acl_security_assert('genuine_0010')",
            "public.authority_schema_security_assert('genuine_0010')",
        ):
            with pytest.raises(
                psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
            ):
                owner.execute(f"SELECT {assertion}")
            owner.rollback()


def test_canonical_project_leaf_identity_accepts_clean_provisioning(
    dedicated_0011_dsn: str,
) -> None:
    """The deterministic public leaf identity keeps ordinary provisioning epoch-stable."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        expected_name = f"derived_state_p_{str(project_id).replace('-', '')}"
        assert owner.execute("SELECT to_regclass(%s)", (f"public.{expected_name}",)).fetchone() != (
            None,
        )
        assert (
            owner.execute("SELECT public.authority_acl_security_assert('genuine_0010')").fetchone()
            is not None
        )
        assert (
            owner.execute(
                "SELECT public.authority_schema_security_assert('genuine_0010')"
            ).fetchone()
            is not None
        )


@pytest.mark.parametrize(
    "coordinated_policy",
    (False, True),
    ids=("rename-only", "rename-with-isolation-policy"),
)
def test_renamed_derived_state_leaf_is_not_a_canonical_project_partition(
    dedicated_0011_dsn: str, coordinated_policy: bool
) -> None:
    """A renamed LIST child remains raw drift even with a matching policy name."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf_name = f"derived_state_p_{str(project_id).replace('-', '')}"
        spoof_name = "derived_state_spoof"
        owner.execute(
            sql.SQL("ALTER TABLE public.{} RENAME TO {}").format(
                sql.Identifier(leaf_name), sql.Identifier(spoof_name)
            )
        )
        if coordinated_policy:
            owner.execute(
                sql.SQL("ALTER POLICY {} ON public.{} RENAME TO {}").format(
                    sql.Identifier(f"{leaf_name}_isolation"),
                    sql.Identifier(spoof_name),
                    sql.Identifier(f"{spoof_name}_isolation"),
                )
            )
        owner.commit()
        for assertion in (
            "public.authority_acl_security_assert('genuine_0010')",
            "public.authority_schema_security_assert('genuine_0010')",
        ):
            with pytest.raises(
                psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
            ):
                owner.execute(f"SELECT {assertion}")
            owner.rollback()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="authority profile drift"
    ):
        apply_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_spoofed_memory_leaf_cannot_hide_behind_coordinated_policy_and_indexes(
    dedicated_0011_dsn: str,
) -> None:
    """Renaming every visible child artifact cannot satisfy the canonical leaf identity."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        leaf_name = f"memory_item_p_{str(project_id).replace('-', '')}"
        spoof_name = "memory_item_spoof"
        index_rows = owner.execute(
            "SELECT index_class.relname "
            "FROM pg_index AS index_data "
            "JOIN pg_class AS index_class ON index_class.oid = index_data.indexrelid "
            "WHERE index_data.indrelid = %s::regclass AND NOT index_data.indisprimary "
            "ORDER BY index_class.relname",
            (f"public.{leaf_name}",),
        ).fetchall()
        owner.execute(
            sql.SQL("ALTER TABLE public.{} RENAME TO {}").format(
                sql.Identifier(leaf_name), sql.Identifier(spoof_name)
            )
        )
        owner.execute(
            sql.SQL("ALTER POLICY {} ON public.{} RENAME TO {}").format(
                sql.Identifier(f"{leaf_name}_isolation"),
                sql.Identifier(spoof_name),
                sql.Identifier(f"{spoof_name}_isolation"),
            )
        )
        for row in index_rows:
            assert len(row) == 1 and isinstance(row[0], str)
            assert row[0].startswith(leaf_name)
            owner.execute(
                sql.SQL("ALTER INDEX public.{} RENAME TO {}").format(
                    sql.Identifier(row[0]), sql.Identifier(spoof_name + row[0][len(leaf_name) :])
                )
            )
        assert owner.execute(
            "SELECT to_regclass(%s) IS NULL", (f"public.{leaf_name}",)
        ).fetchone() == (True,)
        owner.commit()
        for assertion in (
            "public.authority_acl_security_assert('genuine_0010')",
            "public.authority_schema_security_assert('genuine_0010')",
        ):
            with pytest.raises(
                psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
            ):
                owner.execute(f"SELECT {assertion}")
            owner.rollback()


def test_schema_profile_binds_work_queue_persistence(
    dedicated_0011_dsn: str,
) -> None:
    """A profiled control relation cannot be converted to an UNLOGGED table."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("ALTER TABLE public.work_queue SET UNLOGGED")
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


def test_child_column_acl_is_part_of_the_canonical_acl_profile(
    dedicated_0011_dsn: str,
) -> None:
    """Attached leaves cannot hide a column-level grant from the tuple manifest."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        row = owner.execute(
            "SELECT child.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.oid = 'public.memory_item'::regclass "
            "AND pg_get_expr(child.relpartbound, child.oid) = %s",
            (f"FOR VALUES IN ('{project_id}')",),
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        owner.execute("CREATE ROLE tracebed_epoch_intruder NOLOGIN")
        owner.execute(
            sql.SQL("GRANT SELECT (content) ON public.{} TO tracebed_epoch_intruder").format(
                sql.Identifier(row[0])
            )
        )
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_acl_security_assert('genuine_0010')")


def test_schema_profile_rejects_concrete_child_index_shape_drift(
    dedicated_0011_dsn: str,
) -> None:
    """The profile compares child index AM/key ordering/predicate catalogs, not names alone."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        row = owner.execute(
            "SELECT child.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.oid = 'public.memory_status_log'::regclass"
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        leaf_name = row[0]
        index_name = f"{leaf_name}_mem"
        owner.execute(sql.SQL("DROP INDEX public.{}").format(sql.Identifier(index_name)))
        owner.execute(
            sql.SQL("CREATE INDEX {} ON public.{} (memory_id, changed_at)").format(
                sql.Identifier(index_name), sql.Identifier(leaf_name)
            )
        )
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="profile drift"):
        apply_migrations(_attested_dsn(dedicated_0011_dsn))


def test_schema_profile_rejects_a_concrete_child_index_access_method_drift(
    dedicated_0011_dsn: str,
) -> None:
    """An identically named child index using hash cannot stand in for btree."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        row = owner.execute(
            "SELECT child.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.oid = 'public.memory_item'::regclass"
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        leaf_name = row[0]
        index_name = f"{leaf_name}_status"
        owner.execute(sql.SQL("DROP INDEX public.{}").format(sql.Identifier(index_name)))
        owner.execute(
            sql.SQL("CREATE INDEX {} ON public.{} USING hash (status)").format(
                sql.Identifier(index_name), sql.Identifier(leaf_name)
            )
        )
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


@pytest.mark.parametrize(
    "drift",
    ("opclass", "key-order", "predicate", "unique", "missing"),
)
def test_schema_profile_requires_every_concrete_child_index_semantic(
    dedicated_0011_dsn: str, drift: str
) -> None:
    """Leaf indexes bind AM, opclass, key order, predicate, flags, and presence."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        if drift == "opclass":
            parent_name, suffix = "memory_item", "hnsw"
        elif drift == "key-order":
            parent_name, suffix = "memory_status_log", "mem"
        elif drift == "predicate":
            parent_name, suffix = "trace_learning_job", "ready"
        else:
            parent_name, suffix = "memory_item", "status"
        leaf_row = owner.execute(
            "SELECT child.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.relname = %s LIMIT 1",
            (parent_name,),
        ).fetchone()
        assert leaf_row is not None and isinstance(leaf_row[0], str)
        leaf_name = leaf_row[0]
        index_name = f"{leaf_name}_{suffix}"
        owner.execute(sql.SQL("DROP INDEX public.{}").format(sql.Identifier(index_name)))
        if drift == "opclass":
            owner.execute(
                sql.SQL(
                    "CREATE INDEX {} ON public.{} USING hnsw (embedding halfvec_l2_ops)"
                ).format(sql.Identifier(index_name), sql.Identifier(leaf_name))
            )
        elif drift == "key-order":
            owner.execute(
                sql.SQL("CREATE INDEX {} ON public.{} (changed_at DESC, memory_id)").format(
                    sql.Identifier(index_name), sql.Identifier(leaf_name)
                )
            )
        elif drift == "predicate":
            owner.execute(
                sql.SQL(
                    "CREATE INDEX {} ON public.{} "
                    "(pipeline, pipeline_version, available_at, scheduled_at, run_id) "
                    "WHERE state = 'pending'"
                ).format(sql.Identifier(index_name), sql.Identifier(leaf_name))
            )
        elif drift == "unique":
            owner.execute(
                sql.SQL("CREATE UNIQUE INDEX {} ON public.{} (status)").format(
                    sql.Identifier(index_name), sql.Identifier(leaf_name)
                )
            )
        # ``missing`` is deliberately left absent: an invalid/unready index
        # is equally unusable to a reader and is rejected by the same health
        # predicate through its valid/ready/live requirements.
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


@pytest.mark.parametrize("drift", ("role", "extra-policy"))
def test_schema_profile_requires_exact_child_policy_roles_and_count(
    dedicated_0011_dsn: str, drift: str
) -> None:
    """Leaf isolation policy roles and the one-policy cardinality are immutable."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        row = owner.execute(
            "SELECT child.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.oid = 'public.memory_item'::regclass LIMIT 1"
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        leaf_name = row[0]
        if drift == "role":
            owner.execute(
                sql.SQL("ALTER POLICY {} ON public.{} TO tracebed_app").format(
                    sql.Identifier(f"{leaf_name}_isolation"), sql.Identifier(leaf_name)
                )
            )
        else:
            owner.execute(
                sql.SQL("CREATE POLICY {} ON public.{} FOR SELECT TO PUBLIC USING (true)").format(
                    sql.Identifier(f"{leaf_name}_extra"), sql.Identifier(leaf_name)
                )
            )
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


@pytest.mark.parametrize("drift", ("conditional-lookalike", "additional-trigger"))
def test_schema_profile_requires_exact_child_trigger_clones(
    dedicated_0011_dsn: str, drift: str
) -> None:
    """A leaf cannot weaken a cloned terminal guard or add a free-standing guard."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        row = owner.execute(
            "SELECT child.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.oid = 'public.trace_index'::regclass LIMIT 1"
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        leaf_name = row[0]
        guard_name = "trace_index_terminal_immutability_guard"
        if drift == "conditional-lookalike":
            owner.execute(
                sql.SQL(
                    "CREATE TRIGGER {} BEFORE UPDATE ON public.{} "
                    "FOR EACH ROW WHEN (OLD.run_id IS NOT NULL) "
                    "EXECUTE FUNCTION public.trace_index_enforce_terminal_immutability()"
                ).format(sql.Identifier(f"{guard_name}_conditional"), sql.Identifier(leaf_name))
            )
        else:
            owner.execute(
                sql.SQL(
                    "CREATE TRIGGER {} BEFORE UPDATE ON public.{} "
                    "FOR EACH ROW EXECUTE FUNCTION public.trace_index_enforce_terminal_immutability()"
                ).format(sql.Identifier(f"{leaf_name}_extra_guard"), sql.Identifier(leaf_name))
            )
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


@pytest.mark.parametrize("drift", ("default", "storage", "compression"))
def test_schema_profile_requires_exact_child_column_semantics(
    dedicated_0011_dsn: str, drift: str
) -> None:
    """Leaf-only default, storage, and compression mutations are visible."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        _create_active_project_admin(owner)
        ensure_schema_current(owner)
        row = owner.execute(
            "SELECT child.relname FROM pg_inherits AS inheritance "
            "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE parent.oid = 'public.memory_item'::regclass LIMIT 1"
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        leaf_name = row[0]
        if drift == "default":
            statement = "ALTER COLUMN content SET DEFAULT 'leaf-only'"
        elif drift == "storage":
            statement = "ALTER COLUMN content SET STORAGE EXTERNAL"
        else:
            statement = "ALTER COLUMN content SET COMPRESSION lz4"
        owner.execute(
            sql.SQL("ALTER TABLE public.{} {}").format(
                sql.Identifier(leaf_name), sql.SQL(statement)
            )
        )
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


@pytest.mark.parametrize("drift", ("owner", "membership", "policy"))
def test_schema_profile_binds_trusted_owners_memberships_and_policy_roles(
    dedicated_0011_dsn: str, drift: str
) -> None:
    """Schema receipts include trusted ownership, both membership directions, and polroles."""

    _apply_through_0010(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        baseline = owner.execute(
            "SELECT public.authority_schema_security_assert('genuine_0010')"
        ).fetchone()
        assert baseline is not None
        if drift == "owner":
            owner.execute("CREATE ROLE tracebed_epoch_owner NOLOGIN")
            owner.execute("ALTER TABLE public.project OWNER TO tracebed_epoch_owner")
        elif drift == "membership":
            owner.execute("CREATE ROLE tracebed_epoch_member NOLOGIN")
            owner.execute("GRANT tracebed_api_group TO tracebed_epoch_member")
        else:
            _create_active_project_admin(owner)
            ensure_schema_current(owner)
            row = owner.execute(
                "SELECT child.relname FROM pg_inherits AS inheritance "
                "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
                "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
                "WHERE parent.oid = 'public.memory_item'::regclass"
            ).fetchone()
            assert row is not None and isinstance(row[0], str)
            owner.execute(
                sql.SQL("ALTER POLICY {} ON public.{} TO tracebed_app USING (true)").format(
                    sql.Identifier(f"{row[0]}_isolation"), sql.Identifier(row[0])
                )
            )
        owner.commit()
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="canonical expected tuples"
        ):
            owner.execute("SELECT public.authority_schema_security_assert('genuine_0010')")


def test_cutover_refuses_an_unpinned_extension_inventory_without_mutation(
    dedicated_0011_dsn: str,
) -> None:
    """The persistent profile names the complete PG18 extension inventory, including plpgsql."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("CREATE EXTENSION hstore")
        before = owner.execute(
            "SELECT extname, extversion, extnamespace::regnamespace::text "
            "FROM pg_extension ORDER BY extname"
        ).fetchall()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="pinned extension catalog"
    ):
        apply_migrations(_attested_dsn(dedicated_0011_dsn))
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert (
            owner.execute(
                "SELECT extname, extversion, extnamespace::regnamespace::text "
                "FROM pg_extension ORDER BY extname"
            ).fetchall()
            == before
        )


def test_rollback_refuses_an_unexpected_legacy_app_acl_without_erasing_it(
    dedicated_0011_dsn: str,
) -> None:
    """A restored legacy LOGIN must never inherit an owner-planted ACL."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT has_table_privilege('tracebed_app', 'public.yoyo_lock', 'SELECT'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'INSERT'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'UPDATE'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'DELETE')"
        ).fetchone() == (False, False, False, False)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_app PASSWORD 'legacy-password'")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("GRANT SELECT ON public.project TO tracebed_app")
        acl_before = owner.execute(
            "SELECT relacl FROM pg_class WHERE oid = 'public.project'::regclass"
        ).fetchone()
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="profile drift"):
        rollback_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert (
            owner.execute(
                "SELECT relacl FROM pg_class WHERE oid = 'public.project'::regclass"
            ).fetchone()
            == acl_before
        )


def test_direct_rollback_refuses_a_tampered_epoch_chain(
    dedicated_0011_dsn: str,
) -> None:
    """The yoyo rollback repeats the receipt-chain fence independently."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_app PASSWORD 'legacy-password'")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute(
            "ALTER TABLE public.authority_acl_epoch DISABLE TRIGGER authority_acl_epoch_append_guard"
        )
        owner.execute(
            "UPDATE public.authority_acl_epoch SET previous_receipt_digest = decode(repeat('00', 32), 'hex') "
            "WHERE epoch = 1"
        )
        owner.execute(
            "ALTER TABLE public.authority_acl_epoch ENABLE TRIGGER authority_acl_epoch_append_guard"
        )
        owner.commit()

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="invalid epoch receipt chain"
    ):
        rollback_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"


def test_unsafe_existing_foundation_group_blocks_bootstrap_without_role_creation(
    dedicated_0011_dsn: str,
) -> None:
    """Latest bootstrap validates existing authority roles before any CREATE."""

    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("CREATE ROLE tracebed_worker_group LOGIN")
        before = owner.execute(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, "
            "rolbypassrls, rolreplication, rolconnlimit "
            "FROM pg_roles WHERE rolname LIKE 'tracebed_%' ORDER BY rolname"
        ).fetchall()
    with pytest.raises(RuntimeError, match="foundation group does not have required attributes"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        assert (
            owner.execute(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, "
                "rolbypassrls, rolreplication, rolconnlimit "
                "FROM pg_roles WHERE rolname LIKE 'tracebed_%' ORDER BY rolname"
            ).fetchall()
            == before
        )
        assert owner.execute(
            "SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tracebed_app')"
        ).fetchone() == (True,)
        owner.execute("DROP ROLE tracebed_worker_group")

    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"


def test_empty_pre_activity_rollback_keeps_public_hardened(dedicated_0011_dsn: str) -> None:
    """Rollback is allowed only before activity and never reopens PUBLIC."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute("SET ROLE tracebed_api")
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            _insert_authority_v1_trace_event(owner, project_id)
        owner.rollback()
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_app PASSWORD 'legacy-password'")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    assert rollback_migrations(attested) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn) as owner:
        public_connect = owner.execute(
            "SELECT has_database_privilege('public', current_database(), 'CONNECT')"
        ).fetchone()
        assert public_connect in {(False,), None}


def test_rollback_bootstrap_action_quarantines_retries_and_reapplies_cleanly(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner action commits NOLOGIN before a failed yoyo attempt and retries safely."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )

    original_rollback = bootstrap.rollback_migrations
    monkeypatch.setattr(
        bootstrap,
        "rollback_migrations",
        lambda _: (_ for _ in ()).throw(RuntimeError("injected yoyo failure")),
    )
    with pytest.raises(RuntimeError, match="injected yoyo failure"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action="rollback-0011",
        )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rollback_quarantined_at IS NOT NULL, first_activity_at IS NULL "
            "FROM public.authority_cutover_state WHERE singleton"
        ).fetchone() == (True, True)
        assert owner.execute(
            "SELECT bool_and(NOT role.rolcanlogin), "
            "bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM public.authority_cutover_state AS receipt CROSS JOIN pg_roles AS role "
            "JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"

    monkeypatch.setattr(bootstrap, "rollback_migrations", original_rollback)
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="rollback-0011",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT migration_id FROM public._yoyo_migration "
            "ORDER BY applied_at_utc, migration_id, migration_hash"
        ).fetchall() == [
            (migration_id,) for migration_id, _ in bootstrap._YOYO_MIGRATION_HISTORY[:-1]
        ]

    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(role.rolcanlogin), bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM public.authority_cutover_state AS receipt CROSS JOIN pg_roles AS role "
            "JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True)


def test_rollback_quarantine_marker_aborts_a_writer_waiting_on_the_singleton_lock(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A writer queued behind the quarantine lock wakes into the rollback refusal."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = _create_active_project_admin(owner)
        ensure_schema_current(owner)
        owner.commit()
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    started = threading.Event()
    completed = threading.Event()
    failures: list[BaseException] = []

    def writer() -> None:
        try:
            with psycopg.connect(
                _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
            ) as api:
                api.execute("SET application_name = 'tracebed-rollback-writer'")
                started.set()
                _insert_authority_v1_trace_event(api, project_id)
                api.commit()
        except BaseException as exc:  # thread result is asserted below
            failures.append(exc)
        finally:
            completed.set()

    def start_waiting_writer() -> None:
        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        assert started.wait(5)
        with psycopg.connect(attested) as observer:
            for _ in range(40):
                waiting = observer.execute(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE application_name = 'tracebed-rollback-writer' "
                    "AND wait_event_type = 'Lock'"
                ).fetchone()
                if waiting == (1,):
                    return
                time.sleep(0.05)
        raise AssertionError("activity writer did not wait on the quarantine receipt lock")

    monkeypatch.setattr(bootstrap, "_rollback_quarantine_barrier", start_waiting_writer)
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="rollback-0011",
    )
    assert completed.wait(5)
    assert len(failures) == 1
    assert isinstance(failures[0], psycopg.errors.ObjectNotInPrerequisiteState)
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"


def test_direct_0011_rollback_refuses_without_the_ingress_guc(
    dedicated_0011_dsn: str,
) -> None:
    """A quarantine receipt alone cannot make an un-attested yoyo rollback safe."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="trusted ingress"):
        rollback_migrations(dedicated_0011_dsn)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rollback_quarantined_at IS NOT NULL FROM public.authority_cutover_state "
            "WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)


def test_raw_yoyo_apply_and_rollback_cannot_bypass_tracebed_atomic_runner(
    dedicated_0011_dsn: str,
) -> None:
    """An attested raw CLI lacks the repository runner receipt and is inert."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    migrations = read_all_migrations()

    # This is deliberately the upstream mutable API, bypassing `_yoyo_dsn`.
    # It has valid dedicated/ingress assertions but not Tracebed's atomic
    # runner receipt, so 0011 must reject before creating any cutover state.
    with (
        get_backend(_raw_yoyo_dsn(attested)) as backend,
        backend.lock(),
        pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="atomic migration runner"),
    ):
        backend.apply_migrations(backend.to_apply(migrations))
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT to_regclass('public.authority_cutover_state') IS NULL"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_log "
            "WHERE migration_id = '0011_authority_cutover' AND operation = 'apply'"
        ).fetchone() == (0,)

    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)

    with (
        get_backend(_raw_yoyo_dsn(attested)) as backend,
        backend.lock(),
        pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="atomic runner"),
    ):
        backend.rollback_migrations(backend.to_rollback(migrations)[:1])
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rollback_quarantined_at IS NOT NULL FROM public.authority_cutover_state "
            "WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)


@pytest.mark.parametrize(
    "receipt_expression",
    (
        "'infinity'::timestamptz",
        "'-infinity'::timestamptz",
        "cutover_at",
        "activated_at - interval '1 microsecond'",
    ),
    ids=("infinity", "negative-infinity", "equal-cutover", "pre-activation"),
)
def test_rollback_action_refuses_nonmonotonic_or_nonfinite_quarantine_receipts_before_mutation(
    dedicated_0011_dsn: str, receipt_expression: str
) -> None:
    """A forged receipt cannot create the durable rollback NOLOGIN fence."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        constraint = owner.execute(
            "SELECT conname FROM pg_constraint "
            "WHERE conrelid = 'public.authority_cutover_state'::regclass "
            "AND pg_get_constraintdef(oid) LIKE '%ingress_attested_at%'"
        ).fetchone()
        assert constraint is not None and isinstance(constraint[0], str)
        owner.execute(
            sql.SQL("ALTER TABLE public.authority_cutover_state DROP CONSTRAINT {}").format(
                sql.Identifier(constraint[0])
            )
        )
        owner.execute(
            sql.SQL(
                "UPDATE public.authority_cutover_state SET rollback_quarantined_at = {} "
                "WHERE singleton"
            ).format(sql.SQL(receipt_expression))
        )

    with pytest.raises(RuntimeError, match="cutover state is invalid"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action="rollback-0011",
        )
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(receipt.rollback_quarantined_at IS NOT NULL), "
            "bool_and(role.rolcanlogin), bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM public.authority_cutover_state AS receipt CROSS JOIN pg_roles AS role "
            "JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, False, True)


@pytest.mark.parametrize(
    "receipt_expression",
    (
        "'infinity'::timestamptz",
        "'-infinity'::timestamptz",
        "cutover_at",
        "activated_at - interval '1 microsecond'",
    ),
    ids=("infinity", "negative-infinity", "equal-cutover", "pre-activation"),
)
def test_direct_rollback_refuses_nonmonotonic_or_nonfinite_quarantine_receipts(
    dedicated_0011_dsn: str, receipt_expression: str
) -> None:
    """The direct SQL independently rejects receipt tampering after quarantine."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        constraint = owner.execute(
            "SELECT conname FROM pg_constraint "
            "WHERE conrelid = 'public.authority_cutover_state'::regclass "
            "AND pg_get_constraintdef(oid) LIKE '%ingress_attested_at%'"
        ).fetchone()
        assert constraint is not None and isinstance(constraint[0], str)
        owner.execute(
            sql.SQL("ALTER TABLE public.authority_cutover_state DROP CONSTRAINT {}").format(
                sql.Identifier(constraint[0])
            )
        )
        owner.execute(
            sql.SQL(
                "UPDATE public.authority_cutover_state SET rollback_quarantined_at = {} "
                "WHERE singleton"
            ).format(sql.SQL(receipt_expression))
        )

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="pre-activity quarantine"
    ):
        rollback_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(receipt.rollback_quarantined_at IS NOT NULL), "
            "bool_and(NOT role.rolcanlogin), bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM public.authority_cutover_state AS receipt CROSS JOIN pg_roles AS role "
            "JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True, True)


def test_rollback_action_negative_probe_infrastructure_error_keeps_quarantine(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed physical negative probe cannot compensate the committed NOLOGIN fence."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )

    def fail_probe(*_args: object, **_kwargs: object) -> None:
        raise psycopg.OperationalError("injected infrastructure failure")

    monkeypatch.setattr(bootstrap, "_require_credential_rejected", fail_probe)
    with pytest.raises(psycopg.OperationalError, match="injected infrastructure failure"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action="rollback-0011",
        )
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rollback_quarantined_at IS NOT NULL FROM public.authority_cutover_state "
            "WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)


@pytest.mark.parametrize("history_drift", ("unknown", "missing", "duplicate-id"))
def test_rollback_action_authenticates_the_complete_yoyo_history_before_quarantine(
    dedicated_0011_dsn: str, history_drift: str
) -> None:
    """An extra, missing, or duplicate-id yoyo row leaves active roles untouched."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        if history_drift == "unknown":
            owner.execute(
                "INSERT INTO public._yoyo_migration "
                "(migration_hash, migration_id, applied_at_utc) "
                "VALUES (repeat('f', 64), '9999_unknown', clock_timestamp())"
            )
        elif history_drift == "missing":
            owner.execute(
                "DELETE FROM public._yoyo_migration WHERE migration_id = '0010_authority_foundation'"
            )
        else:
            owner.execute(
                "INSERT INTO public._yoyo_migration "
                "(migration_hash, migration_id, applied_at_utc) "
                "VALUES (repeat('e', 64), '0010_authority_foundation', clock_timestamp())"
            )

    with pytest.raises(RuntimeError, match="exact yoyo migration history"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action="rollback-0011",
        )
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(receipt.rollback_quarantined_at IS NULL), "
            "bool_and(role.rolcanlogin), bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM public.authority_cutover_state AS receipt CROSS JOIN pg_roles AS role "
            "JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, False, True)


def test_direct_rollback_authenticates_yoyo_history_after_quarantine(
    dedicated_0011_dsn: str,
) -> None:
    """Direct 0011 SQL rechecks the real locked yoyo table before mutation."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "INSERT INTO public._yoyo_migration "
            "(migration_hash, migration_id, applied_at_utc) "
            "VALUES (repeat('f', 64), '9999_unknown', clock_timestamp())"
        )

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="exact yoyo migration history"
    ):
        rollback_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(receipt.rollback_quarantined_at IS NOT NULL), "
            "bool_and(NOT role.rolcanlogin), bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM public.authority_cutover_state AS receipt CROSS JOIN pg_roles AS role "
            "JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True, True)


@pytest.mark.parametrize(
    ("migration_id", "timestamp_expression"),
    (
        ("0001_registries", "'-infinity'::timestamp"),
        ("0011_authority_cutover", "'infinity'::timestamp"),
        ("0010_authority_foundation", "clock_timestamp()::timestamp"),
    ),
    ids=("negative-infinity-first", "infinity-tip", "finite-out-of-order"),
)
def test_direct_rollback_refuses_nonfinite_or_out_of_order_yoyo_history_timestamps(
    dedicated_0011_dsn: str, migration_id: str, timestamp_expression: str
) -> None:
    """Every direct rollback history timestamp is finite and strictly ordered evidence."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "UPDATE public._yoyo_migration SET applied_at_utc = {} WHERE migration_id = %s"
            ).format(sql.SQL(timestamp_expression)),
            (migration_id,),
        )

    with pytest.raises(
        psycopg.errors.ObjectNotInPrerequisiteState, match="exact yoyo migration history"
    ):
        rollback_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        history = owner.execute(
            "SELECT applied_at_utc::text FROM public._yoyo_migration WHERE migration_id = %s",
            (migration_id,),
        ).fetchone()
        assert history is not None and isinstance(history[0], str)
        assert owner.execute(
            "SELECT rollback_quarantined_at IS NOT NULL FROM public.authority_cutover_state "
            "WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT bool_and(NOT role.rolcanlogin), "
            "bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True)


@pytest.mark.parametrize(
    "failure_boundary",
    ("after-sql", "log-error", "after-log", "unmark-error"),
)
def test_atomic_0011_rollback_failure_never_commits_partial_ddl_log_or_history(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch, failure_boundary: str
) -> None:
    """Every yoyo SQL/log/unmark boundary rolls back on the same PG18 transaction."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    seam_name = {
        "after-sql": "_atomic_rollback_after_sql_barrier",
        "log-error": "_atomic_rollback_log_migration",
        "after-log": "_atomic_rollback_after_log_barrier",
        "unmark-error": "_atomic_rollback_unmark_migration",
    }[failure_boundary]
    original = getattr(pg_migrate, seam_name)

    def fail_boundary(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"injected atomic rollback {failure_boundary}")

    monkeypatch.setattr(pg_migrate, seam_name, fail_boundary)
    with pytest.raises(RuntimeError, match=f"injected atomic rollback {failure_boundary}"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
            action="rollback-0011",
        )

    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rollback_quarantined_at IS NOT NULL, first_activity_at IS NULL "
            "FROM public.authority_cutover_state WHERE singleton"
        ).fetchone() == (True, True)
        assert owner.execute(
            "SELECT profile FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1"
        ).fetchone() == ("cutover_0011",)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_log "
            "WHERE migration_id = '0011_authority_cutover' AND operation = 'rollback'"
        ).fetchone() == (0,)
        assert owner.execute(
            "SELECT bool_and(NOT role.rolcanlogin), "
            "bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True)

    monkeypatch.setattr(pg_migrate, seam_name, original)
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
        action="rollback-0011",
    )
    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT to_regclass('public.authority_cutover_state') IS NULL"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_log "
            "WHERE migration_id = '0011_authority_cutover' AND operation = 'rollback'"
        ).fetchone() == (1,)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_migration WHERE migration_id = '0011_authority_cutover'"
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    "failure_boundary",
    ("after-sql", "log-error", "after-log", "mark-error"),
)
def test_atomic_0011_apply_failure_never_commits_partial_ddl_log_or_history(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch, failure_boundary: str
) -> None:
    """Forward 0011 SQL, audit log, and mark share one PG18 transaction."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    seam_name = {
        "after-sql": "_atomic_apply_after_sql_barrier",
        "log-error": "_atomic_apply_log_migration",
        "after-log": "_atomic_apply_after_log_barrier",
        "mark-error": "_atomic_apply_mark_migration",
    }[failure_boundary]
    original = getattr(pg_migrate, seam_name)

    def fail_boundary(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"injected atomic apply {failure_boundary}")

    monkeypatch.setattr(pg_migrate, seam_name, fail_boundary)
    with pytest.raises(RuntimeError, match=f"injected atomic apply {failure_boundary}"):
        apply_migrations(attested)

    assert current_revision(dedicated_0011_dsn)[0] == "0010_authority_foundation"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT to_regclass('public.authority_cutover_state') IS NULL"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT profile FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1"
        ).fetchone() == ("genuine_0010",)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_log "
            "WHERE migration_id = '0011_authority_cutover' AND operation = 'apply'"
        ).fetchone() == (0,)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_migration WHERE migration_id = '0011_authority_cutover'"
        ).fetchone() == (0,)
        assert owner.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'tracebed_app'"
        ).fetchone() == (False,)
        assert owner.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (0,)

    monkeypatch.setattr(pg_migrate, seam_name, original)
    assert apply_migrations(attested) == ["0011_authority_cutover"]


def test_atomic_initial_0001_failure_rolls_back_schema_log_and_mark(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same wrapper protects the first transactional migration, too."""

    def fail_first_migration(_backend: object, migration: object) -> None:
        if getattr(migration, "id", None) == "0001_registries":
            raise RuntimeError("injected atomic initial apply")

    monkeypatch.setattr(pg_migrate, "_atomic_apply_after_sql_barrier", fail_first_migration)
    with pytest.raises(RuntimeError, match="injected atomic initial apply"):
        apply_migrations(dedicated_0011_dsn)

    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute("SELECT to_regclass('public.project') IS NULL").fetchone() == (True,)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_migration WHERE migration_id = '0001_registries'"
        ).fetchone() == (0,)
        assert owner.execute(
            "SELECT count(*) FROM public._yoyo_log "
            "WHERE migration_id = '0001_registries' AND operation = 'apply'"
        ).fetchone() == (0,)


def test_0011_rollback_refuses_receipt_count_drift_without_erasing_quarantine(
    dedicated_0011_dsn: str,
) -> None:
    """The locked v0 data counts are rollback evidence, not repair targets."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "UPDATE public.authority_cutover_state "
            "SET legacy_dead_letter_rows = legacy_dead_letter_rows + 1 WHERE singleton"
        )

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="history/count drift"):
        rollback_migrations(attested)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT rollback_quarantined_at IS NOT NULL FROM public.authority_cutover_state "
            "WHERE singleton"
        ).fetchone() == (True,)
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)


def test_rollback_reapply_returns_split_roles_to_staged_passwordless_state(
    dedicated_0011_dsn: str,
) -> None:
    """A permitted rollback is an exact, subsequently reapplicable 0011 stage."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_app PASSWORD 'legacy-password'")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    assert rollback_migrations(attested) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT role.rolname, role.rolcanlogin, auth.rolpassword IS NULL, auth.rolvaliduntil IS NULL "
            "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker') ORDER BY role.rolname"
        ).fetchall() == [
            ("tracebed_api", False, True, True),
            ("tracebed_worker", False, True, True),
        ]
        assert owner.execute(
            "SELECT has_table_privilege('tracebed_app', 'public.yoyo_lock', 'SELECT'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'INSERT'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'UPDATE'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'DELETE')"
        ).fetchone() == (False, False, False, False)

    assert apply_migrations(attested) == ["0011_authority_cutover"]
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(role.rolcanlogin), bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
            "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True)
        assert owner.execute(
            "SELECT has_table_privilege('tracebed_app', 'public.yoyo_lock', 'SELECT'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'INSERT'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'UPDATE'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'DELETE')"
        ).fetchone() == (False, False, False, False)


def test_rollback_restores_the_full_effective_0010_app_acl_matrix(
    dedicated_0011_dsn: str,
) -> None:
    """0011 rollback restores 0010 exceptions, not broad table DML."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    with psycopg.connect(dedicated_0011_dsn) as owner:
        project_id = uuid4()
        owner.execute(
            "INSERT INTO project (project_id, name, status) VALUES (%s, %s, 'active')",
            (project_id, f"cutover-acl-{project_id.hex}"),
        )
        owner.execute(
            "UPDATE project SET status = 'suspended' WHERE project_id = %s", (project_id,)
        )
        ensure_schema_current(owner)
        owner.commit()
    before = _app_acl_surface(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_app PASSWORD 'legacy-password'")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )
    _quarantine_for_pre_activity_rollback(dedicated_0011_dsn)
    assert rollback_migrations(attested) == ["0011_authority_cutover"]
    after = _app_acl_surface(dedicated_0011_dsn)
    expected_tables: list[tuple[object, ...]] = []
    for row in cast(list[tuple[object, ...]], before[0]):
        if row[0] == "yoyo_lock":
            expected_tables.append((row[0], row[1], False, False, False, False))
        else:
            expected_tables.append(row)
    assert after == (expected_tables, before[1], before[2], before[3])
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT has_table_privilege('tracebed_app', 'public.trace_index', 'DELETE'), "
            "has_table_privilege('tracebed_app', 'public.trace_learning_job', 'DELETE'), "
            "has_table_privilege('tracebed_app', 'public.principal_grant', 'INSERT'), "
            "has_table_privilege('tracebed_app', 'public.run_owner', 'UPDATE'), "
            "has_table_privilege('tracebed_app', 'public.yoyo_lock', 'SELECT')"
        ).fetchone() == (False, False, False, False, False)
        owner.execute("CREATE TABLE public.rollback_default_acl_probe (id integer)")
        assert owner.execute(
            "SELECT has_table_privilege('tracebed_app', 'public.rollback_default_acl_probe', 'SELECT'), "
            "has_table_privilege('tracebed_app', 'public.rollback_default_acl_probe', 'INSERT')"
        ).fetchone() == (False, False)
        owner.execute("DROP TABLE public.rollback_default_acl_probe")
        owner.commit()


def test_activation_setting_drift_leaves_both_split_roles_nologin(
    dedicated_0011_dsn: str,
) -> None:
    """Post-commit/pre-activation drift is not repaired or partially activated."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("ALTER ROLE tracebed_api SET search_path = 'pg_catalog'")
    with pytest.raises(RuntimeError, match="protected role or database settings"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)
        owner.execute("ALTER ROLE tracebed_api RESET ALL")
    bootstrap.bootstrap_database(
        dedicated_0011_dsn,
        "legacy-password",
        "api-password",
        "worker-password",
        "dedicated",
        ingress_quarantined=True,
    )


def test_activation_refuses_direct_column_acl_drift(
    dedicated_0011_dsn: str,
) -> None:
    """Column-level tokenizer grants participate in the authority receipt."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("REVOKE SELECT (name) ON tokenizer_catalog.tokenizer FROM tracebed_api_group")

    with pytest.raises(RuntimeError, match="authority epoch profile is not current"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)


def test_activation_refuses_future_object_default_acl_drift(
    dedicated_0011_dsn: str,
) -> None:
    """A future-object grant is fenced before it can become a live table ACL."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO tracebed_api_group"
        )

    with pytest.raises(RuntimeError, match="authority epoch profile is not current"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)


def test_activation_refuses_tampered_epoch_receipt_chain(
    dedicated_0011_dsn: str,
) -> None:
    """A restored trigger cannot hide an epoch predecessor/receipt rewrite."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    with psycopg.connect(dedicated_0011_dsn) as owner:
        owner.execute(
            "ALTER TABLE public.authority_acl_epoch DISABLE TRIGGER authority_acl_epoch_append_guard"
        )
        owner.execute(
            "UPDATE public.authority_acl_epoch SET previous_receipt_digest = decode(repeat('00', 32), 'hex') "
            "WHERE epoch = 1"
        )
        owner.execute(
            "ALTER TABLE public.authority_acl_epoch ENABLE TRIGGER authority_acl_epoch_append_guard"
        )
        owner.commit()

    with pytest.raises(RuntimeError, match="authority epoch profile is not current"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT bool_and(NOT rolcanlogin) FROM pg_roles "
            "WHERE rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True,)


def test_unactivated_login_residue_is_terminated_and_recovered_in_one_bootstrap(
    dedicated_0011_dsn: str,
) -> None:
    """A crash between credential commit and receipt marking is retry-safe."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_api LOGIN PASSWORD 'api-password'")
        owner.execute("ALTER ROLE tracebed_worker LOGIN PASSWORD 'worker-password'")

    # NOLOGIN does not evict a pre-crash backend.  The recovery path disables
    # both identities, waits for the PG18 bounded termination primitive, and
    # only then republishes the receipt/credentials.
    with psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT activated_at IS NOT NULL, first_activity_at IS NULL "
            "FROM public.authority_cutover_state WHERE singleton"
        ).fetchone() == (True, True)


@pytest.mark.parametrize("drift", ("api-group-login", "api-group-membership"))
def test_marker_null_residue_preserves_split_evidence_when_non_split_fence_drifts(
    dedicated_0011_dsn: str, drift: str
) -> None:
    """A safe split residue is never normalized before all other roles validate."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_api LOGIN PASSWORD 'api-password'")
        owner.execute("ALTER ROLE tracebed_worker LOGIN PASSWORD 'worker-password'")
        if drift == "api-group-login":
            owner.execute("ALTER ROLE tracebed_api_group LOGIN PASSWORD 'group-password'")
        else:
            owner.execute("CREATE ROLE tracebed_residue_member NOLOGIN")
            owner.execute("GRANT tracebed_api_group TO tracebed_residue_member")

    with psycopg.connect(_role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")) as held:
        with psycopg.connect(dedicated_0011_dsn) as owner:
            before_roles = owner.execute(
                "SELECT role.rolname, role.rolcanlogin, auth.rolpassword, auth.rolvaliduntil "
                "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
                "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker') ORDER BY role.rolname"
            ).fetchall()
            before_sessions = owner.execute(
                "SELECT pid, usename FROM pg_stat_activity "
                "WHERE pid <> pg_backend_pid() AND usename IN ('tracebed_api', 'tracebed_worker') "
                "ORDER BY pid"
            ).fetchall()
            owner.commit()

        with pytest.raises(RuntimeError):
            bootstrap.bootstrap_database(
                dedicated_0011_dsn,
                "legacy-password",
                "api-password",
                "worker-password",
                "dedicated",
                ingress_quarantined=True,
            )

        assert held.execute("SELECT 1").fetchone() == (1,)
        with psycopg.connect(dedicated_0011_dsn) as owner:
            after_roles = owner.execute(
                "SELECT role.rolname, role.rolcanlogin, auth.rolpassword, auth.rolvaliduntil "
                "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
                "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker') ORDER BY role.rolname"
            ).fetchall()
            after_sessions = owner.execute(
                "SELECT pid, usename FROM pg_stat_activity "
                "WHERE pid <> pg_backend_pid() AND usename IN ('tracebed_api', 'tracebed_worker') "
                "ORDER BY pid"
            ).fetchall()
            assert owner.execute(
                "SELECT activated_at IS NULL FROM public.authority_cutover_state WHERE singleton"
            ).fetchone() == (True,)
        assert after_roles == before_roles
        assert after_sessions == before_sessions
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"


@pytest.mark.parametrize(
    "receipt_case",
    ("earlier", "later", "infinity"),
    ids=("earlier", "later", "infinity"),
)
def test_cutover_refuses_a_tampered_ingress_attestation_receipt_before_activation(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch, receipt_case: str
) -> None:
    """The durable attestation receipt is an exact timestamp, never a boolean."""

    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(_attested_dsn(dedicated_0011_dsn)) == ["0011_authority_cutover"]
    receipt_expressions = {
        "earlier": sql.SQL("cutover_at - interval '1 microsecond'"),
        "later": sql.SQL("cutover_at + interval '1 microsecond'"),
        "infinity": sql.SQL("'infinity'::timestamptz"),
    }

    def tamper_after_profile_validation() -> None:
        # This test-owned superuser bypasses just the new database CHECK after
        # the authenticated profile has passed. It proves the Python reader
        # independently refuses a forged, unequal/non-finite receipt.
        with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
            constraint = owner.execute(
                "SELECT conname FROM pg_constraint "
                "WHERE conrelid = 'public.authority_cutover_state'::regclass "
                "AND pg_get_constraintdef(oid) LIKE '%ingress_attested_at%'"
            ).fetchone()
            assert constraint is not None and isinstance(constraint[0], str)
            owner.execute(
                sql.SQL("ALTER TABLE public.authority_cutover_state DROP CONSTRAINT {}").format(
                    sql.Identifier(constraint[0])
                )
            )
            owner.execute(
                sql.SQL(
                    "UPDATE public.authority_cutover_state "
                    "SET ingress_attested_at = {} WHERE singleton"
                ).format(receipt_expressions[receipt_case])
            )

    monkeypatch.setattr(
        bootstrap, "_cutover_state_validation_barrier", tamper_after_profile_validation
    )
    with pytest.raises(RuntimeError, match=r"cutover (state|ingress receipt) is invalid"):
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
    with psycopg.connect(dedicated_0011_dsn) as owner:
        assert owner.execute(
            "SELECT (SELECT activated_at IS NULL FROM public.authority_cutover_state WHERE singleton), "
            "bool_and(NOT role.rolcanlogin), bool_and(auth.rolpassword IS NULL) "
            "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
            "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker')"
        ).fetchone() == (True, True, True)
    assert current_revision(dedicated_0011_dsn)[0] == "0011_authority_cutover"


def test_login_residue_session_race_is_terminated_before_fresh_activation(
    dedicated_0011_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session opened during quarantine cannot survive into fresh activation."""

    attested = _attested_dsn(dedicated_0011_dsn)
    _apply_through_0010(dedicated_0011_dsn)
    _harden_legacy_role_for_cutover(dedicated_0011_dsn)
    assert apply_migrations(attested)[-1] == "0011_authority_cutover"
    with psycopg.connect(dedicated_0011_dsn, autocommit=True) as owner:
        owner.execute("SET password_encryption = 'scram-sha-256'")
        owner.execute("ALTER ROLE tracebed_api LOGIN PASSWORD 'api-password'")
        owner.execute("ALTER ROLE tracebed_worker LOGIN PASSWORD 'worker-password'")

    original_quarantine = bootstrap._quarantine_split_roles
    raced_session: psycopg.Connection[tuple[object, ...]] | None = None

    def open_then_quarantine(conn: psycopg.Connection[object]) -> None:
        nonlocal raced_session
        raced_session = psycopg.connect(
            _role_dsn(dedicated_0011_dsn, "tracebed_api", "api-password")
        )
        original_quarantine(conn)

    monkeypatch.setattr(bootstrap, "_quarantine_split_roles", open_then_quarantine)
    try:
        bootstrap.bootstrap_database(
            dedicated_0011_dsn,
            "legacy-password",
            "api-password",
            "worker-password",
            "dedicated",
            ingress_quarantined=True,
        )
        assert raced_session is not None
        with pytest.raises(psycopg.OperationalError):
            raced_session.execute("SELECT 1")
        with psycopg.connect(dedicated_0011_dsn) as owner:
            assert owner.execute(
                "SELECT bool_and(role.rolcanlogin), bool_and(auth.rolpassword LIKE 'SCRAM-SHA-256$%') "
                "FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid "
                "WHERE role.rolname IN ('tracebed_api', 'tracebed_worker')"
            ).fetchone() == (True, True)
            assert owner.execute(
                "SELECT activated_at IS NOT NULL FROM public.authority_cutover_state WHERE singleton"
            ).fetchone() == (True,)
    finally:
        if raced_session is not None:
            raced_session.close()
    monkeypatch.setattr(bootstrap, "_quarantine_split_roles", original_quarantine)
