"""Offline, comment-stripped contract pins for the staged 0011 authority cutover."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.ddl import partition_grant_statements, partition_name

pytestmark = pytest.mark.phase3

_MIGRATIONS = Path(__file__).parents[2] / "migrations"
_PROJECT = ProjectId("12345678-1234-5678-1234-567812345678")


def _sql(name: str) -> str:
    """Strip comments so security assertions cannot be satisfied by prose."""

    text = (_MIGRATIONS / name).read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return "\n".join(line.split("--", 1)[0] for line in text.splitlines())


def _profile_manifest_rows(source: str) -> tuple[tuple[str, str, str], ...]:
    """Read the literal, checked-in expected tuple fixture without SQL execution."""

    start = source.index("-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_BEGIN")
    end = source.index("-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_END")
    rows = re.findall(
        r"\('([a-z0-9_]+)'::public\.authority_acl_profile, "
        r"'([a-z]+)', decode\('([0-9a-f]{64})', 'hex'\)\)",
        source[start:end],
    )
    return tuple(rows)


def _manifest_generator() -> object:
    path = Path(__file__).parents[2] / "scripts" / "generate_authority_acl_profile_manifest.py"
    spec = importlib.util.spec_from_file_location("authority_acl_manifest_generator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cutover_is_attested_dedicated_cluster_transactional_and_role_staged() -> None:
    forward = _sql("0011_authority_cutover.sql")
    assert (_MIGRATIONS / "0011_authority_cutover.sql").read_text(encoding="utf-8").startswith(
        "-- depends: 0010_authority_foundation"
    )
    assert "current_setting('tracebed.cluster_scope', true) IS DISTINCT FROM 'dedicated'" in forward
    assert "(SELECT count(*) FROM pg_database) <> 4" in forward
    assert "'postgres', 'template0', 'template1'" in forward
    assert "datallowconn IS FALSE" in forward
    assert "IN ACCESS EXCLUSIVE MODE" in forward
    raw_forward = (_MIGRATIONS / "0011_authority_cutover.sql").read_text(encoding="utf-8")
    assert raw_forward.index("tracebed.ingress_quarantined") < raw_forward.index("IN ACCESS EXCLUSIVE MODE")
    assert raw_forward.index("tracebed.atomic_migration_runner") < raw_forward.index(
        "IN ACCESS EXCLUSIVE MODE"
    )
    assert "current_setting('tracebed.ingress_quarantined', true) IS DISTINCT FROM 'on'" in forward
    for relation in (
        "project",
        "principal",
        "agent_type",
        "agent_registration",
        "principal_grant",
        "run_owner",
        "work_queue",
        "dead_letter",
        "outcome_event",
        "trace_index",
        "trace_learning_job",
    ):
        assert relation in forward.split("IN ACCESS EXCLUSIVE MODE", 1)[0]
    for role in ("tracebed_api", "tracebed_worker"):
        assert f"CREATE ROLE {role} NOLOGIN INHERIT" in forward
        assert f"ALTER ROLE {role} RESET ALL" in forward
    assert "GRANT tracebed_api_group TO tracebed_api WITH ADMIN FALSE, INHERIT TRUE, SET FALSE" in forward
    assert "GRANT tracebed_worker_group TO tracebed_worker WITH ADMIN FALSE, INHERIT TRUE, SET FALSE" in forward
    assert "ALTER ROLE tracebed_app NOLOGIN" in forward
    assert "pg_auth_members" in forward
    assert "pg_shdepend" in forward
    assert "rolconfig IS NOT NULL" in forward
    assert "pg_db_role_setting" in forward


def test_yoyo_ini_is_read_only_and_0011_requires_the_tracebed_atomic_runner() -> None:
    """No documented raw mutable CLI route can bypass the atomic wrapper."""

    ini = (_MIGRATIONS / "yoyo.ini").read_text(encoding="utf-8")
    forward = _sql("0011_authority_cutover.sql")
    rollback = _sql("0011_authority_cutover.rollback.sql")
    assert "yoyo list" in ini
    assert "yoyo apply" not in ini
    assert "yoyo rollback" not in ini
    for source in (forward, rollback):
        assert "current_setting('tracebed.atomic_migration_runner', true)" in source


def test_cutover_receipt_marker_v1_boundary_and_public_hardening_are_explicit() -> None:
    forward = _sql("0011_authority_cutover.sql")
    assert "CREATE TABLE public.authority_cutover_state" in forward
    assert "cutover_at timestamptz NOT NULL" in forward
    assert "activated_at timestamptz" in forward
    assert "ingress_attested_at timestamptz NOT NULL" in forward
    assert "isfinite(ingress_attested_at)" in forward
    assert "ingress_attested_at = cutover_at" in forward
    assert "isfinite(activated_at)" in forward
    assert "isfinite(first_activity_at)" in forward
    assert "rollback_quarantined_at timestamptz" in forward
    assert "rollback_quarantined_at IS NULL" in forward
    assert "isfinite(rollback_quarantined_at)" in forward
    assert "rollback_quarantined_at >= activated_at" in forward
    assert "first_activity_at IS NULL OR rollback_quarantined_at IS NULL" in forward
    assert "legacy_dead_letter_rows bigint NOT NULL" in forward
    assert "legacy_outcome_rows bigint NOT NULL" in forward
    assert "CREATE FUNCTION public.tracebed_mark_authority_activity() RETURNS void" in forward
    assert "CREATE FUNCTION public.tracebed_mark_authority_activity_trigger() RETURNS trigger" in forward
    assert "PERFORM public.tracebed_mark_authority_activity()" in forward
    assert "GRANT EXECUTE ON FUNCTION public.tracebed_mark_authority_activity()" not in forward
    assert "AFTER INSERT ON work_queue" in forward
    assert "AFTER INSERT ON dead_letter" in forward
    assert "AFTER INSERT ON outcome_event" in forward
    assert "AFTER INSERT ON run_owner" in forward
    assert "authority cutover is not activated" in forward
    assert "authority_version IS NOT NULL AND authority_version = 1" in forward
    assert "IS DISTINCT FROM 1" in forward
    assert "ALTER TABLE work_queue ALTER COLUMN authority_version DROP DEFAULT" in forward
    assert "work_queue_authority_v1_only_ck" in forward
    assert "dead_letter_require_authority_v1_guard" in forward
    assert "outcome_event_require_authority_v1_guard" in forward
    assert "REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC" in forward
    assert "REVOKE USAGE, CREATE ON SCHEMA public FROM PUBLIC" in forward
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON ROUTINES FROM PUBLIC" in forward
    assert "REVOKE CONNECT ON DATABASE %I FROM tracebed_app, tracebed_erasure_group" in forward
    assert "public.%I" in forward
    assert "tokenizer_catalog.tokenize(text, text)" in forward
    assert "bm25_catalog.to_bm25query(regclass, bm25_catalog.bm25vector)" in forward
    assert "bm25_catalog.search_bm25query(" in forward
    assert "_vchord_bm25_cast_array_to_bm25vector" in forward
    assert "public.cosine_distance(halfvec, halfvec)" in forward
    assert "GRANT EXECUTE ON FUNCTION bm25_catalog.bm25_page_inspect" not in forward
    assert "GRANT EXECUTE ON FUNCTION %s" not in forward
    assert "GRANT SELECT (name, config) ON tokenizer_catalog.tokenizer, tokenizer_catalog.text_analyzer" in forward
    assert "ON ALL TABLES" not in forward
    assert "ON ALL SEQUENCES" not in forward
    assert "ON ALL ROUTINES" not in forward


def test_active_grant_recheck_is_a_narrow_api_only_security_definer_lock() -> None:
    forward = _sql("0011_authority_cutover.sql")
    rollback = _sql("0011_authority_cutover.rollback.sql")
    start = forward.index("CREATE FUNCTION public.tracebed_require_active_grant(")
    end = forward.index("CREATE TRIGGER work_queue_authority_activity", start)
    helper = forward[start:end]

    assert "RETURNS TABLE (grant_id uuid, role text, feedback_source text)" in helper
    assert "LANGUAGE plpgsql SECURITY DEFINER" in helper
    assert "SET search_path = pg_catalog, pg_temp" in helper
    assert "session_user IS DISTINCT FROM 'tracebed_api'" in helper
    assert "pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')" in helper
    assert "current_setting('tracebed.project_id', true)" in helper
    for relation in (
        "public.principal",
        "public.agent_registration",
        "public.project",
        "public.agent_type",
        "public.principal_grant",
    ):
        assert relation in helper
    assert "FOR SHARE OF principal, registration, project, agent_type, principal_grant" in helper
    assert "GRANT EXECUTE ON FUNCTION public.tracebed_require_active_grant" in forward
    assert "TO tracebed_api_group" in forward
    assert "tracebed_worker_group" in forward
    assert "DROP FUNCTION public.tracebed_require_active_grant" in rollback


def test_authority_epoch_v2_binds_acl_and_schema_digests() -> None:
    foundation = _sql("0010_authority_foundation.sql")
    forward = _sql("0011_authority_cutover.sql")
    rollback = _sql("0011_authority_cutover.rollback.sql")

    for source in (foundation, forward, rollback):
        assert "profile_version" in source
        assert "source_schema_digest" in source
        assert "result_schema_digest" in source
    assert "tracebed.authority-acl-receipt/v2" in foundation
    assert "CREATE FUNCTION public.authority_acl_security_assert(" in foundation
    assert "CREATE FUNCTION public.authority_schema_security_assert(" in foundation
    assert "SET search_path = pg_catalog, pg_temp" in foundation
    assert "authority cutover refuses authority profile drift" in forward
    assert "authority cutover refuses an unauthenticated digest helper" in forward
    assert "authority_acl_epoch_receipt" in forward
    assert "authority_acl_profile_actual_tuples" in forward
    assert "authority_acl_profile_tuple" in foundation
    assert "EXCEPT" in foundation
    assert "authority_schema_profile_actual_tuples" in foundation
    assert "canonical expected tuples" in foundation
    assert "NEW.source_acl_digest IS DISTINCT FROM NEW.result_acl_digest" in foundation
    assert "NEW.source_acl_digest IS DISTINCT FROM predecessor.result_acl_digest" in foundation
    assert "source_acl_digest = predecessor_acl_digest" in rollback
    assert "source_schema_digest = predecessor_schema_digest" in rollback
    assert "result_acl_digest = public.authority_acl_security_assert('genuine_0010')" in (
        _sql("0010_authority_foundation.rollback.sql")
    )


def test_acl_profile_fixture_is_checked_in_immutable_contract_data() -> None:
    """No migration may turn the observed catalog into an expected baseline."""

    foundation_raw = (_MIGRATIONS / "0010_authority_foundation.sql").read_text(encoding="utf-8")
    rows = _profile_manifest_rows(foundation_raw)
    assert rows == tuple(sorted(rows))
    assert len(rows) == len(set(rows))
    assert {profile for profile, _, _ in rows} == {
        "genuine_0010",
        "cutover_0011",
        "cutover_0012",
        "hardened_0010",
    }
    assert {tuple_class for _, tuple_class, _ in rows} == {"acl", "schema"}
    assert len(rows) > 6_000

    generator = _manifest_generator()
    rendered = generator.render_manifest(reversed(rows))
    marker_start = foundation_raw.index("-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_BEGIN")
    marker_end = foundation_raw.index("-- GENERATED_AUTHORITY_ACL_PROFILE_TUPLES_END")
    fixture = foundation_raw[marker_start:marker_end]
    assert rendered in fixture

    generator_source = (
        Path(__file__).parents[2] / "scripts" / "generate_authority_acl_profile_manifest.py"
    ).read_text(encoding="utf-8")
    assert "_without_profile_literal_and_epoch" in generator_source
    assert '_actual_rows(connection, "genuine_0010")' in generator_source
    assert '_actual_rows(connection, "cutover_0011")' in generator_source
    assert '_actual_rows(connection, "hardened_0010")' in generator_source
    assert "No production migration imports this file" in generator_source
    # The private generator can INSERT independently collected rows only to
    # drive the next clean transition.  It must never use the checked-in
    # profile table as a source of provenance.
    assert "FROM public.authority_acl_profile_tuple" not in generator_source
    assert "authority_acl_profile_actual_tuples" in generator_source
    assert "authority_schema_profile_actual_tuples" in generator_source

    for name in (
        "0010_authority_foundation.sql",
        "0011_authority_cutover.sql",
        "0011_authority_cutover.rollback.sql",
    ):
        source = _sql(name)
        assert not re.search(
            r"INSERT\s+INTO\s+public\.authority_acl_profile_tuple[\s\S]{0,600}"
            r"FROM\s+public\.authority_(?:acl|schema)_profile_actual_tuples",
            source,
            flags=re.IGNORECASE,
        )
    foundation = _sql("0010_authority_foundation.sql")
    assert "authority_acl_profile_tuple_guard" in foundation
    assert "BEFORE INSERT OR UPDATE OR DELETE ON public.authority_acl_profile_tuple" in foundation


def test_acl_profile_contract_covers_dedicated_databases_and_all_table_like_acls() -> None:
    foundation = _sql("0010_authority_foundation.sql")
    for database in ("'postgres'", "'template0'", "'template1'"):
        assert database in foundation
    assert "relation.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')" in foundation
    assert "CASE WHEN relation.relkind = 'S' THEN 's'::\"char\" ELSE 'r'::\"char\" END" in foundation
    assert "pg_parameter_acl" in foundation
    for rollback in (
        _sql("0010_authority_foundation.rollback.sql"),
        _sql("0011_authority_cutover.rollback.sql"),
    ):
        assert "unauthenticated digest helper" in rollback
        assert "authority_acl_profile_actual_tuples" in rollback
        assert "authority_schema_profile_actual_tuples" in rollback


def test_acl_receipt_normalizes_partition_acl_identity_by_parent_and_bound() -> None:
    """A renamed leaf cannot hide an ACL delta behind its physical relname."""

    foundation = _sql("0010_authority_foundation.sql")
    assert "partition_acl_mismatch" in foundation
    assert "pg_catalog.pg_get_expr(child.relpartbound, child.oid)" in foundation
    assert "partition-acl:' || parent_name || ':' || partition_bound" in foundation


def test_schema_profile_pins_full_concrete_partition_and_yoyo_semantics() -> None:
    """The dynamic-project health bit is structural, not a name-only probe."""

    foundation = _sql("0010_authority_foundation.sql")
    for token in (
        "opclass_defaults",
        "index_data.indisvalid",
        "index_data.indisready",
        "index_data.indislive",
        "index_data.indnkeyatts",
        "index_data.indnatts",
        "index_data.indoption",
        "index_data.indcollation",
        "index_data.indexprs",
        "index_data.indpred",
        "child_policy.polroles",
        "policy_member(role_oid, ordinality)",
        "child_trigger.tgqual::text",
        "child_trigger.tgattr::smallint[]",
        "parent_trigger.tgattr::smallint[]",
        "child_trigger.tgoldtable",
        "child_trigger.tgnewtable",
        "child_trigger.tgconstraint",
        "child_trigger.tgdeferrable",
        "child_trigger.tginitdeferred",
        "child_attribute.attstorage",
        "child_attribute.attcompression",
        "pg_catalog.pg_get_expr(child_default.adbin, child_default.adrelid)",
        "authority foundation refuses a noncanonical yoyo lock topology",
        "public._yoyo_lock",
        "yoyo_lock_locked_not_null",
        "yoyo_lock_pkey",
        "index_data.indisprimary AND index_data.indisvalid",
        "index_data.indcheckxmin",
        "index_data.indisclustered",
        "index_data.indisreplident",
        "index_data.indnullsnotdistinct",
        "index_data.indimmediate",
        "index_class.relpersistence = 'p'",
        "canonical_project_partition",
        "child.relname = parent.relname || '_p_' || replace(bound_project.project_id::text, '-', '')",
        "relation.relpersistence",
        "relation.relreplident",
        "relation.reloptions",
    ):
        assert token in foundation
    # Attached child names are deliberately absent from the semantic ACL
    # identity; the parent and immutable LIST bound define the leaf instead.
    assert "parent_name IN ('genuine_0010', 'hardened_0010')" not in foundation
    assert "WHEN profile::text IN ('genuine_0010', 'hardened_0010')" in foundation
    assert "partition_acl_metadata_mismatch" in foundation
    assert "SELECT oid, rolname FROM pg_catalog.pg_roles" in foundation
    for acl_class in (
        "pg_tablespace",
        "pg_language",
        "pg_foreign_data_wrapper",
        "pg_foreign_server",
        "pg_largeobject_metadata",
    ):
        assert acl_class in foundation


def test_schema_profile_covers_control_shape_extension_and_concrete_partition_metadata() -> None:
    foundation = _sql("0010_authority_foundation.sql")
    for relation in (
        "project_config",
        "agent_type_config",
        "killswitch_state",
        "embedding_model",
        "scoring_epoch",
        "work_queue_id_seq",
        "scoring_epoch_epoch_id_seq",
        "yoyo_lock",
    ):
        assert f"'{relation}'" in foundation
    for catalog in (
        "pg_extension",
        "pg_identify_object",
        "pg_policy",
        "pg_trigger",
        "pg_index",
        "pg_parameter_acl",
    ):
        assert catalog in foundation
    for field in (
        "polroles",
        "tgqual",
        "tgoldtable",
        "tgnewtable",
        "atttypmod",
        "attcollation",
        "attgenerated",
        "attidentity",
        "attstorage",
        "attcompression",
        "indnkeyatts",
        "indcollation",
        "indisclustered",
        "indnullsnotdistinct",
    ):
        assert field in foundation
    assert "trace_index_enforce_terminal_immutability" in foundation
    assert "trace_index_enforce_terminal'," not in foundation
    assert "('plpgsql', '1.0', 'pg_catalog')" in _sql("0011_authority_cutover.sql")


def test_cutover_acl_reconstruction_has_no_all_object_wildcards() -> None:
    """Profile equality precedes explicit ACL reconstruction; no wildcard DDL."""

    forward = _sql("0011_authority_cutover.sql")
    rollback = _sql("0011_authority_cutover.rollback.sql")
    for source in (forward, rollback):
        assert "ON ALL TABLES" not in source
        assert "ON ALL SEQUENCES" not in source
        assert "ON ALL ROUTINES" not in source
        assert "REVOKE ALL PRIVILEGES" not in source
    assert "REVOKE EXECUTE ON FUNCTION %s" in forward
    assert "REVOKE USAGE ON TYPE %s" in forward


def test_rollback_is_monotonic_and_does_not_restore_public_privileges() -> None:
    rollback = _sql("0011_authority_cutover.rollback.sql")
    assert rollback.count("DO $$") == 2
    assert "first_activity_at IS NOT NULL" in rollback
    assert "tracebed.ingress_quarantined" in rollback
    assert "ingress_attested_at IS DISTINCT FROM cutover_state.cutover_at" in rollback
    assert "NOT isfinite(cutover_state.cutover_at)" in rollback
    assert "NOT isfinite(cutover_state.activated_at)" in rollback
    assert "NOT isfinite(cutover_state.rollback_quarantined_at)" in rollback
    assert "rollback_quarantined_at < cutover_state.activated_at" in rollback
    assert "public._yoyo_migration" in rollback
    assert "exact yoyo migration history" in rollback
    assert "NOT isfinite(actual.applied_at_utc)" in rollback
    assert "cutover history/count drift" in rollback
    assert "tracebed.cluster_scope" in rollback
    assert "max_prepared_transactions" in rollback
    assert "ALTER ROLE tracebed_api NOLOGIN" in rollback
    assert "ALTER ROLE tracebed_worker NOLOGIN" in rollback
    assert "ALTER ROLE tracebed_api NOLOGIN PASSWORD NULL" in rollback
    assert "ALTER ROLE tracebed_worker NOLOGIN PASSWORD NULL" in rollback
    assert "rollback failed to restore staged split role" in rollback
    assert "ALTER ROLE tracebed_app NOLOGIN" in rollback
    assert "ALTER ROLE tracebed_app LOGIN" not in rollback
    assert "committed pre-activity quarantine" in rollback
    assert "rollback_quarantined_at IS NULL" in rollback
    assert "GRANT CONNECT ON DATABASE" in rollback
    assert "work_queue_authority_v0_v1_ck" in rollback
    assert "topic IN ('trace_event', 'memory_proposal')" in rollback
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES" not in rollback
    assert not re.search(r"\bGRANT\b[^;]*\bTO\s+PUBLIC\b", rollback, flags=re.IGNORECASE)
    assert "GRANT CONNECT ON DATABASE" in rollback


@pytest.mark.parametrize(
    ("table", "api", "worker"),
    [
        ("memory_item", "SELECT", "SELECT, INSERT, UPDATE"),
        ("trace_subject", None, "SELECT, INSERT"),
        ("subject_key", None, "SELECT, INSERT"),
        ("blackboard_entry", None, None),
        ("trace_learning_job", None, "SELECT, INSERT, UPDATE"),
        ("run_owner", "SELECT, INSERT", "SELECT"),
    ],
)
def test_future_children_use_the_cutover_acl_matrix(
    table: str, api: str | None, worker: str | None
) -> None:
    name = f"public.{partition_name(table, _PROJECT)}"
    statements = partition_grant_statements(table, _PROJECT, authority_cutover=True)
    joined = " ".join(statements)
    assert f"REVOKE ALL PRIVILEGES ON {name} FROM PUBLIC" in joined
    assert "tracebed_app" in joined and "tracebed_erasure_group" in joined
    if api is None:
        assert "TO tracebed_api_group" not in joined
    else:
        assert f"GRANT {api} ON {name} TO tracebed_api_group" in joined
    if worker is None:
        assert "TO tracebed_worker_group" not in joined
    else:
        assert f"GRANT {worker} ON {name} TO tracebed_worker_group" in joined
