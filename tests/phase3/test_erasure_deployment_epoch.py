"""Offline E4 deployment-epoch and fixed-composition regressions."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tracebed.domain.errors import ConfigError
from tracebed.erasure.composition import COMPOSE_ERASURE_MANIFEST, _validate_environment
from tracebed.stores.pg.authority_dsn import RuntimeDsnError, runtime_dsn_from_environment
from tracebed.stores.pg.ddl import PARTITIONED_TABLES

pytestmark = pytest.mark.phase3

_ROOT = Path(__file__).parents[2]
_FORWARD = (_ROOT / "migrations" / "0013_erasure_deployment.sql").read_text(encoding="utf-8")
_ROLLBACK = (_ROOT / "migrations" / "0013_erasure_deployment.rollback.sql").read_text(
    encoding="utf-8"
)
_REPO = (_ROOT / "src" / "tracebed" / "stores" / "pg" / "repo.py").read_text(
    encoding="utf-8"
)
_FOUNDATION = (_ROOT / "migrations" / "0010_authority_foundation.sql").read_text(
    encoding="utf-8"
)


def _final_function(source: str, name: str) -> str:
    """Return the deployed (last) SQL definition, not a historical draft."""

    start = source.rindex(f"CREATE FUNCTION public.{name}")
    return source[start : source.index("\n$$;", start) + len("\n$$;")]


def test_e4_is_a_new_closed_c12_epoch_and_does_not_edit_accepted_sources() -> None:
    assert _FORWARD.startswith("-- depends: 0012_erasure_saga")
    assert _ROLLBACK.startswith("-- depends: 0012_erasure_saga")
    assert "exact c12 yoyo history" in _FORWARD
    assert "admissions_open IS FALSE" in _FORWARD
    assert "no runtime sessions or live erasure leases" in _FORWARD
    assert "CREATE ROLE tracebed_erasure" in _FORWARD
    assert (
        "NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        in _FORWARD
    )
    assert "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE" in _FORWARD
    assert "first_executor_activity_at" in _FORWARD
    assert "erasure_deployment_security_assert" in _FORWARD
    assert "erasure deployment rollback requires closed preactivity drain" in _ROLLBACK
    assert "ALTER ROLE tracebed_erasure NOLOGIN PASSWORD NULL" in _ROLLBACK


def test_e4_fixed_manifest_and_readiness_rebind_api_worker_and_erasure() -> None:
    assert "erasure_deployment_tuple" in _FORWARD
    assert "erasure_deployment_epoch" in _FORWARD
    assert "parent_authority_receipt" in _FORWARD
    assert "tracebed_erasure_prepublication_readiness" in _FORWARD
    assert "tracebed_erasure_readiness" in _FORWARD
    assert "CREATE OR REPLACE FUNCTION public.tracebed_runtime_prepublication_readiness" in _FORWARD
    assert "CREATE OR REPLACE FUNCTION public.tracebed_runtime_readiness" in _FORWARD
    assert "CREATE OR REPLACE FUNCTION public.tracebed_open_authority_admission" in _FORWARD


def test_e4_epoch_receipt_uses_timezone_invariant_timestamp_framing() -> None:
    """The same stored deployment instant must hash identically in every session zone."""

    receipt = _FORWARD[
        _FORWARD.index("CREATE FUNCTION public.erasure_deployment_epoch_receipt") : _FORWARD.index(
            "CREATE FUNCTION public.erasure_deployment_state_guard"
        )
    ]
    assert "timestamptz_send(transitioned)" in receipt
    assert "transitioned::text" not in receipt


def test_e4_primary_batch_scopes_outer_partition_ctids_and_restores_c12_on_rollback() -> None:
    """A ctid is leaf-local, so E4 must pin the outer project predicate too."""

    forward_start = _FORWARD.index(
        "CREATE OR REPLACE FUNCTION public.tracebed_erasure_primary_batch("
    )
    primary = _FORWARD[forward_start : _FORWARD.index("-- The fixed manifest", forward_start)]
    scoped = "row.project_id = expected_project_id AND row.ctid IN"
    assert primary.count("row.ctid IN") >= 20
    assert primary.count("row.ctid IN") == primary.count(scoped)
    assert "tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer)" in _FORWARD
    assert "(SELECT count(*) FROM public.erasure_deployment_tuple) <> 34 THEN" in _FORWARD

    rollback_start = _ROLLBACK.index("-- Restore c12's exact primary-batch definition.")
    rollback = _ROLLBACK[
        rollback_start : _ROLLBACK.index("DROP TRIGGER erasure_request_executor_activity", rollback_start)
    ]
    assert rollback.count("row.ctid IN") >= 20
    assert scoped not in rollback


def test_e4_closes_the_terminal_project_key_and_worker_acl_seams() -> None:
    """E4 extends only the profiled project sentinel, never raw table ACLs."""

    writer = _FORWARD[
        _FORWARD.index("CREATE OR REPLACE FUNCTION public.tracebed_insert_subject_key_v2") : _FORWARD.index(
            "CREATE FUNCTION public.tracebed_erasure_run_subject_digests"
        )
    ]
    assert "expected_subject_digest = ANY(capability.subject_digests)" in writer
    assert "expected_subject_digest = public.tracebed_subject_digest(" in writer
    assert "expected_project_id, '__project__'" in writer

    reader = _FORWARD[
        _FORWARD.index("CREATE FUNCTION public.tracebed_erasure_run_subject_digests") : _FORWARD.index(
            "-- The fixed manifest"
        )
    ]
    assert "FROM public.trace_subject AS binding" in reader
    assert "RETURN actual_digests;" in reader
    assert "tracebed_assert_erasure_write_allowed" not in reader
    assert "GRANT EXECUTE ON FUNCTION public.tracebed_erasure_run_subject_digests(uuid,uuid)" in _FORWARD
    assert "DROP FUNCTION public.tracebed_erasure_run_subject_digests(uuid,uuid);" in _ROLLBACK
    assert "CREATE OR REPLACE FUNCTION public.tracebed_insert_subject_key_v2" in _ROLLBACK

    runtime_assertion = _REPO[
        _REPO.index("_ASSERT_ERASURE_RUN_WRITE_SQL") : _REPO.index("# `trace_index`", _REPO.index("_ASSERT_ERASURE_RUN_WRITE_SQL"))
    ]
    assert "tracebed_erasure_run_subject_digests" in runtime_assertion
    assert "tracebed_assert_erasure_write_allowed" in runtime_assertion
    assert "FROM trace_subject" not in runtime_assertion


def test_e4_successor_receipt_binds_complete_c12_acl_schema_and_e4_role_control() -> None:
    """E4 must not turn c12's canonical authority profiles into blind spots."""

    assert "erasure_deployment_authority_acl_digest" in _FORWARD
    assert "authority_acl_profile_actual_tuples" in _FORWARD
    assert "erasure_deployment_authority_schema_digest" in _FORWARD
    assert "authority_schema_profile_actual_tuples" in _FORWARD
    assert "erasure_deployment_role_control_digest" in _FORWARD
    assert "pg_db_role_setting" in _FORWARD
    assert "DROP FUNCTION public.erasure_deployment_authority_acl_digest();" in _ROLLBACK


def test_authenticated_catalog_assertions_prelock_only_parents_in_ddl_order() -> None:
    """Readiness cannot invert provisioning's parent-lock acquisition order."""

    expected_locks = tuple(
        f"LOCK TABLE ONLY public.{parent} IN ACCESS SHARE MODE;" for parent in PARTITIONED_TABLES
    )
    expected_names = tuple(PARTITIONED_TABLES)
    acl = _final_function(_FOUNDATION, "authority_acl_security_assert(")
    schema = _final_function(_FOUNDATION, "authority_schema_security_assert(")
    deployment = _final_function(_FORWARD, "erasure_deployment_security_assert()")

    for assertion in (acl, schema):
        assert "LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER" in assertion
        assert tuple(
            re.findall(r"LOCK TABLE ONLY public\.([a-z_]+) IN ACCESS SHARE MODE;", assertion)
        ) == expected_names
        assert assertion.index(expected_locks[0]) < assertion.index("IF EXISTS (")
        assert assertion.index(expected_locks[16]) < assertion.index(
            "IF profile = 'cutover_0012'::public.authority_acl_profile THEN"
        )
        assert assertion.index(expected_locks[17]) > assertion.index(
            "IF profile = 'cutover_0012'::public.authority_acl_profile THEN"
        )

    assert "LANGUAGE plpgsql VOLATILE SECURITY INVOKER" in deployment
    assert tuple(
        re.findall(r"LOCK TABLE ONLY public\.([a-z_]+) IN ACCESS SHARE MODE;", deployment)
    ) == expected_names
    assert deployment.index(expected_locks[0]) < deployment.index("IF EXISTS (")


def test_erasure_runtime_dsn_is_exactly_three_way_exclusive() -> None:
    valid = {
        "TB_ERASURE_DB_DSN": "postgresql://tracebed_erasure:secret@postgres-erasure/tracebed"
    }
    assert runtime_dsn_from_environment("tracebed_erasure", valid).role == "tracebed_erasure"
    for conflicting in ("TB_API_DB_DSN", "TB_WORKER_DB_DSN"):
        with pytest.raises(RuntimeDsnError):
            runtime_dsn_from_environment("tracebed_erasure", valid | {conflicting: "attacker"})


def test_e4_composition_is_fixed_and_rejects_raw_or_cross_runtime_inputs() -> None:
    assert COMPOSE_ERASURE_MANIFEST == (
        "graph_postgres",
        "trace_s3_v1",
        "valkey_v1",
        "vector_postgres",
    )
    valid = {
        "TB_ERASURE_DB_DSN": "postgresql://tracebed_erasure:secret@postgres-erasure/tracebed",
        "TB_STORAGE__VALKEY_URL": "valkey://valkey:6379/0",
        "TB_STORAGE__TRACESTORE__DRIVER": "s3",
        "TB_STORAGE__TRACESTORE__ENDPOINT": "http://seaweedfs:8333",
        "TB_STORAGE__TRACESTORE__BUCKET": "tracebed-traces",
        "TB_STORAGE__TRACESTORE__REGION": "us-east-1",
        "TB_STORAGE__TRACESTORE__ACCESS_KEY_ENV": "TB_S3_ERASURE_ACCESS_KEY_FILE",
        "TB_STORAGE__TRACESTORE__SECRET_KEY_ENV": "TB_S3_ERASURE_SECRET_KEY_FILE",
    }
    _validate_environment(valid)
    for forbidden in ("TB_API_DB_DSN", "TB_WORKER_DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "PGHOST"):
        with pytest.raises(ConfigError):
            _validate_environment(valid | {forbidden: "attacker"})
