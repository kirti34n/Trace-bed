"""Offline contract pins for the 0010 authority foundation migration."""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.phase3

_MIGRATIONS = Path(__file__).parents[2] / "migrations"


def _statements(sql: str) -> str:
    """Exclude prose: schema/grant assertions must match executable SQL."""

    return "\n".join(line.split("--", 1)[0] for line in sql.splitlines())


def _forward() -> str:
    return _statements((_MIGRATIONS / "0010_authority_foundation.sql").read_text(encoding="utf-8"))


def _raw_forward() -> str:
    return (_MIGRATIONS / "0010_authority_foundation.sql").read_text(encoding="utf-8")


def _rollback() -> str:
    return _statements(
        (_MIGRATIONS / "0010_authority_foundation.rollback.sql").read_text(encoding="utf-8")
    )


def test_authority_foundation_has_the_expected_dependency_preflight_and_safe_groups() -> None:
    sql = _forward()
    assert _raw_forward().startswith("-- depends: 0009_trace_index_terminal_freeze")
    for role in ("tracebed_api_group", "tracebed_worker_group", "tracebed_erasure_group"):
        assert role in sql
    for attribute in (
        "NOLOGIN",
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOINHERIT",
        "NOBYPASSRLS",
        "NOREPLICATION",
        "CONNECTION LIMIT -1",
    ):
        assert attribute in sql
    for table in (
        "project",
        "principal",
        "agent_type",
        "agent_registration",
        "work_queue",
        "dead_letter",
        "trace_index",
        "trace_learning_job",
        "outcome_event",
    ):
        assert table in sql.split("IN ACCESS EXCLUSIVE MODE", 1)[0]
    assert "USING ERRCODE = '55000'" in sql
    assert "pg_auth_members" in sql
    assert "membership.member OR group_role.oid = membership.roleid" in sql
    assert "pg_shdepend" in sql
    assert "SELECT defaclrole FROM pg_default_acl" in sql
    assert "dependency.deptype IN ('a', 'i', 'r', 't', 'o')" in sql
    assert "missing_roles text[]" in sql
    assert "privilege.is_grantable" in sql
    assert "acl_entry.grantor IS DISTINCT FROM acl_entry.owner_oid" in sql
    for parent in ("trace_learning_job", "trace_index"):
        assert f"ALTER TABLE {parent} NO FORCE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE {parent} DISABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE {parent} ENABLE ROW LEVEL SECURITY" in sql
        assert f"ALTER TABLE {parent} FORCE ROW LEVEL SECURITY" in sql


def test_registry_guards_and_backfill_are_explicit_and_narrow() -> None:
    sql = _forward()
    for function in (
        "project_enforce_lifecycle",
        "principal_enforce_immutability",
        "agent_type_enforce_immutability",
        "agent_registration_enforce_immutability",
        "principal_grant_enforce_immutability",
    ):
        assert f"CREATE FUNCTION {function}" in sql
    assert "project_deleted_at_shape_ck" in sql
    assert "agent_type_project_identity_uq" in sql
    assert "agent_registration_agent_type_project_fk" in sql
    assert "principal_grant_registration_fk" in sql
    assert "principal_grant_grantor_registration_fk" in sql
    assert "principal_grant_one_active_role_uq" in sql
    assert "'data', NULL" in sql
    assert "project.status IN ('active', 'suspended')" in sql
    assert "principal.revoked_at IS NULL" in sql
    assert "registration.revoked_at IS NULL" in sql
    assert "CREATE TRIGGER" in sql and "BEFORE INSERT OR UPDATE OR DELETE ON principal" in sql


def test_run_owner_queue_dead_and_outcome_authority_shapes_are_versioned() -> None:
    sql = _forward()
    assert "CREATE TABLE run_owner" in sql
    assert "PARTITION BY LIST (project_id)" in sql
    assert "ALTER TABLE run_owner FORCE ROW LEVEL SECURITY" in sql
    assert "CREATE FUNCTION run_owner_enforce_immutability" in sql
    assert "ON CONFLICT (project_id, run_id) DO NOTHING" in sql
    assert "subject_digests_are_valid" in sql
    assert "REVOKE EXECUTE ON FUNCTION subject_digests_are_valid(bytea[]) FROM PUBLIC" in sql
    for table in ("work_queue", "dead_letter", "outcome_event"):
        assert f"{table}_authority_version_ck" in sql
        assert f"{table}_authority_v0_v1_ck" in sql
    assert "work_queue_subject_digests_gin_idx" in sql
    assert "dead_letter_subject_digests_gin_idx" in sql
    assert "adapter = feedback_source" in sql
    assert sql.count("feedback_source IS NOT NULL") >= 3


def test_group_grants_are_narrow_and_rollback_refuses_populated_authority_state() -> None:
    sql = _forward()
    assert "GRANT SELECT, INSERT ON work_queue TO tracebed_api_group" in sql
    assert "GRANT SELECT, UPDATE, DELETE ON work_queue TO tracebed_worker_group" in sql
    assert "GRANT SELECT, INSERT ON dead_letter TO tracebed_worker_group" in sql
    assert "GRANT SELECT, INSERT ON run_owner TO tracebed_app, tracebed_api_group" in sql
    assert "GRANT SELECT ON run_owner TO tracebed_worker_group" in sql
    assert "tracebed_erasure_group" in sql

    rollback = _rollback()
    for refusal in (
        "principal grants",
        "run owners",
        "v1 authority rows",
        "subject digests",
        "revoked registrations",
        "deleting projects",
    ):
        assert refusal in rollback
    assert "USING ERRCODE = '55000'" in rollback
    assert "IN ACCESS EXCLUSIVE MODE" in rollback
    for attribute in (
        "rolcanlogin",
        "rolsuper",
        "rolcreatedb",
        "rolcreaterole",
        "rolinherit",
        "rolbypassrls",
        "rolreplication",
        "rolconnlimit",
    ):
        assert f"role_state.{attribute}" in rollback
    assert "membership.member OR group_role.oid = membership.roleid" in rollback
    assert "privilege.is_grantable" in rollback
    assert "unexpected group access dependencies" in rollback
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES" not in rollback
    assert "REVOKE ALL PRIVILEGES ON ALL SEQUENCES" not in rollback
    for parent in ("run_owner", "outcome_event"):
        assert f"ALTER TABLE {parent} NO FORCE ROW LEVEL SECURITY" in rollback
        assert f"ALTER TABLE {parent} DISABLE ROW LEVEL SECURITY" in rollback
    for parent in ("outcome_event",):
        assert f"ALTER TABLE {parent} ENABLE ROW LEVEL SECURITY" in rollback
        assert f"ALTER TABLE {parent} FORCE ROW LEVEL SECURITY" in rollback
    assert "DROP TABLE IF EXISTS run_owner CASCADE" in rollback
    assert "DROP TABLE IF EXISTS principal_grant CASCADE" in rollback


def test_dual_mode_backfill_and_rollback_have_no_hidden_authority_shortcuts() -> None:
    """Pin sequencing and the absence of an accidental future-DATA trigger."""

    raw = _raw_forward()
    backfill = raw.index("INSERT INTO principal_grant (principal_id, project_id, role, granted_by)")
    preflight = raw.index("ALTER TABLE trace_learning_job NO FORCE ROW LEVEL SECURITY")
    assert "set_config('tracebed.project_id'" not in raw[preflight:backfill]
    assert "ALTER TABLE trace_index DISABLE ROW LEVEL SECURITY" in raw[preflight:backfill]
    assert "CREATE TRIGGER" not in raw[backfill: raw.index("CREATE TABLE run_owner", backfill)]
    assert "feedback_source IN ('verdict', 'correction_adapter', 'downstream')" in _forward()
    assert "'implicit'" not in _forward()[raw.index("CREATE TABLE principal_grant") :]

    from yoyo.migrations import read_sql_migration

    _, _, rollback_steps = read_sql_migration(str(_MIGRATIONS / "0010_authority_foundation.rollback.sql"))
    assert len(rollback_steps) == 1


def test_work_and_dead_authority_envelopes_are_identical_and_groups_cannot_mutate_registry() -> None:
    sql = _forward()
    authority_columns = (
        "authority_version",
        "run_id",
        "source_principal_id",
        "source_agent_type_id",
        "source_grant_id",
        "required_role",
        "feedback_source",
        "run_owner_principal_id",
        "run_owner_agent_type_id",
        "subject_digests",
    )
    for column in authority_columns:
        expected = 3 if column in {
            "authority_version",
            "source_agent_type_id",
            "source_grant_id",
            "feedback_source",
            "run_owner_principal_id",
            "run_owner_agent_type_id",
        } else 2
        assert sql.count(f"ADD COLUMN {column}") == expected
    for table in ("work_queue", "dead_letter"):
        assert f"{table}_authority_version_ck" in sql
        assert f"{table}_authority_v0_v1_ck" in sql
        assert f"{table}_subject_digests_ck" in sql

    for group in ("tracebed_api_group", "tracebed_worker_group"):
        assert f"GRANT UPDATE ON principal_grant TO {group}" not in sql
        assert f"GRANT INSERT ON principal_grant TO {group}" not in sql
    assert "status IN ('active', 'suspended')" in sql
    assert "project.deleted_at IS NULL" in sql
    assert "principal.revoked_at IS NULL" in sql
