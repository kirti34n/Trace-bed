"""Scratch-Postgres checks for 0010 authority DDL; skips without owner DSN."""

from __future__ import annotations

import os
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql

from tests.phase2.trace_e2e_support import scratch_dsn as scratch_dsn
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg import bootstrap
from tracebed.stores.pg.migrate import apply_migrations, current_revision, rollback_migrations
from tracebed.stores.pg.partitions import _drop_project_for_pre_e3_test_only as drop_project
from tracebed.stores.pg.partitions import create_project_partitions, ensure_schema_current

pytestmark = [pytest.mark.phase3, pytest.mark.integration]


def _rollback_to_0009(dsn: str) -> None:
    assert rollback_migrations(dsn) == ["0010_authority_foundation"]


def _sentinel(conn: psycopg.Connection[Any], relation: str) -> int:
    row = conn.execute(
        sql.SQL("SELECT sentinel FROM {}").format(sql.Identifier(relation))
    ).fetchone()
    assert row is not None and isinstance(row[0], int)
    return row[0]


def _legacy_identity(
    conn: psycopg.Connection[Any],
    *,
    status: str = "active",
    revoked_principal: bool = False,
) -> tuple[UUID, UUID, UUID]:
    project_id, principal_id, agent_type_id = uuid4(), uuid4(), uuid4()
    deleted_at = "now()" if status == "deleted" else "NULL"
    conn.execute(
        f"INSERT INTO project (project_id, name, status, deleted_at) "  # noqa: S608 - fixed test SQL
        f"VALUES (%s, %s, %s, {deleted_at})",
        (project_id, f"authority-{project_id.hex}", status),
    )
    if revoked_principal:
        conn.execute(
            "INSERT INTO principal (principal_id, kind, external_ref, revoked_at) "
            "VALUES (%s, 'oidc_sub', %s, now())",
            (principal_id, f"authority-{principal_id.hex}"),
        )
    else:
        conn.execute(
            "INSERT INTO principal (principal_id, kind, external_ref) VALUES (%s, 'oidc_sub', %s)",
            (principal_id, f"authority-{principal_id.hex}"),
        )
    conn.execute(
        "INSERT INTO agent_type (agent_type_id, project_id, name) VALUES (%s, %s, %s)",
        (agent_type_id, project_id, f"agent-{agent_type_id.hex}"),
    )
    conn.execute(
        "INSERT INTO agent_registration (principal_id, project_id, agent_type_id) VALUES (%s, %s, %s)",
        (principal_id, project_id, agent_type_id),
    )
    return project_id, principal_id, agent_type_id


def _expect_check_violation(
    conn: psycopg.Connection[Any], sql: str, params: tuple[object, ...] = ()
) -> None:
    """Prove one rejected mutation without discarding the test's setup rows."""

    conn.execute("SAVEPOINT authority_rejection")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(sql, params)
    conn.execute("ROLLBACK TO SAVEPOINT authority_rejection")
    conn.execute("RELEASE SAVEPOINT authority_rejection")


def _create_trace_partition(conn: psycopg.Connection[Any], project_id: UUID) -> None:
    conn.execute(
        f"CREATE TABLE trace_index_p_{project_id.hex} PARTITION OF trace_index "
        f"FOR VALUES IN ('{project_id}')"
    )


def test_authority_foundation_backfills_only_safe_registrations_and_enforces_rls(
    scratch_dsn: str,
) -> None:
    with psycopg.connect(scratch_dsn) as conn:
        # A fresh migration has no registrations, which is the only safe
        # rollback/reapply state.  The parent is FORCE RLS and unscoped reads
        # therefore reveal no run owner rows to an ordinary app role.
        row = conn.execute("SELECT count(*) FROM principal_grant").fetchone()
        assert row == (0,)
        row = conn.execute("SELECT relforcerowsecurity FROM pg_class WHERE relname = 'run_owner'").fetchone()
        assert row == (True,)
        groups = conn.execute(
            "SELECT rolname, rolcanlogin, rolinherit, rolbypassrls "
            "FROM pg_roles WHERE rolname IN ('tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group')"
        ).fetchall()
        assert len(groups) == 3
        assert all(row[1:] == (False, False, False) for row in groups)


def test_empty_authority_foundation_rolls_back_and_reapplies(scratch_dsn: str) -> None:
    rolled = rollback_migrations(scratch_dsn)
    assert rolled == ["0010_authority_foundation"]
    assert apply_migrations(scratch_dsn) == ["0010_authority_foundation"]


def test_rollback_refuses_an_orphan_run_owner_row_without_losing_force_rls(
    scratch_dsn: str,
) -> None:
    """Rollback must inspect every child, not only project-registry UUIDs."""

    project_id, run_id, principal_id, agent_type_id = uuid4(), uuid4(), uuid4(), uuid4()
    child_name = f"run_owner_p_{project_id.hex}"
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            f"CREATE TABLE {child_name} PARTITION OF run_owner FOR VALUES IN ('{project_id}')"
        )
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        conn.execute(
            "INSERT INTO run_owner "
            "(project_id, run_id, principal_id, agent_type_id, origin, bound_at) "
            "VALUES (%s, %s, %s, %s, 'trace', now())",
            (project_id, run_id, principal_id, agent_type_id),
        )
        conn.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        rollback_migrations(scratch_dsn)
    assert "0010_authority_foundation" in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        security = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'run_owner'::regclass"
        ).fetchone()
        assert security == (True, True)
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        assert conn.execute(
            "SELECT count(*) FROM run_owner WHERE project_id = %s AND run_id = %s",
            (project_id, run_id),
        ).fetchone() == (1,)


def test_rollback_refuses_a_v1_outcome_without_losing_force_rls(scratch_dsn: str) -> None:
    """Outcome provenance is checked with RLS disabled before column removal."""

    with psycopg.connect(scratch_dsn) as conn:
        project_id, principal_id, agent_type_id = _legacy_identity(conn)
        ensure_schema_current(conn)
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        conn.execute(
            "INSERT INTO outcome_event "
            "(event_id, run_id, project_id, principal_id, adapter, r, authority_version, "
            "source_agent_type_id, source_grant_id, feedback_source, "
            "run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, %s, %s, %s, 'verdict', 1.0, 1, %s, %s, 'verdict', %s, %s)",
            (uuid4(), uuid4(), project_id, principal_id, agent_type_id, uuid4(), principal_id, agent_type_id),
        )
        conn.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        rollback_migrations(scratch_dsn)
    assert "0010_authority_foundation" in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        assert conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'outcome_event'::regclass"
        ).fetchone() == (True, True)


def test_run_owner_partition_name_collision_refuses_without_marking_0010(scratch_dsn: str) -> None:
    """A same-name ordinary table must never masquerade as an attached child."""

    _rollback_to_0009(scratch_dsn)
    project_id = uuid4()
    child_name = f"run_owner_p_{project_id.hex}"
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "INSERT INTO project (project_id, name, status) VALUES (%s, %s, 'active')",
            (project_id, f"authority-collision-{project_id.hex}"),
        )
        conn.execute(f"CREATE TABLE {child_name} (sentinel integer NOT NULL DEFAULT 7)")
        conn.execute(f"INSERT INTO {child_name} DEFAULT VALUES")
        conn.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        assert _sentinel(conn, child_name) == 7
        assert conn.execute("SELECT to_regclass('public.run_owner')").fetchone() == (None,)


def test_generic_partition_collision_refuses_and_attached_child_remains_idempotent(
    scratch_dsn: str,
) -> None:
    project_id = uuid4()
    collision_name = f"memory_item_p_{project_id.hex}"
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "INSERT INTO project (project_id, name, status) VALUES (%s, %s, 'active')",
            (project_id, f"partition-collision-{project_id.hex}"),
        )
        conn.execute(f"CREATE TABLE {collision_name} (sentinel integer NOT NULL DEFAULT 9)")
        conn.execute(f"INSERT INTO {collision_name} DEFAULT VALUES")
        conn.commit()

        with pytest.raises(RuntimeError, match="unexpected relation"):
            create_project_partitions(conn, ProjectId(project_id))
        assert _sentinel(conn, collision_name) == 9
        with pytest.raises(RuntimeError, match="unexpected relation"):
            drop_project(conn, ProjectId(project_id))
        assert _sentinel(conn, collision_name) == 9

        conn.execute(f"DROP TABLE {collision_name}")
        create_project_partitions(conn, ProjectId(project_id))
        create_project_partitions(conn, ProjectId(project_id))
        assert conn.execute(
            "SELECT EXISTS ("
            "SELECT 1 FROM pg_inherits AS inheritance "
            "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
            "WHERE child.relname = %s AND inheritance.inhparent = 'run_owner'::regclass"
            ")",
            (f"run_owner_p_{project_id.hex}",),
        ).fetchone() == (True,)
        drop_project(conn, ProjectId(project_id))
        assert conn.execute("SELECT to_regclass(%s)", (collision_name,)).fetchone() == (None,)
        assert conn.execute(
            "SELECT to_regclass(%s)", (f"run_owner_p_{project_id.hex}",)
        ).fetchone() == (None,)


def test_partition_lifecycle_pins_children_to_public_under_owner_schema_shadow(
    scratch_dsn: str,
) -> None:
    """Owner ``$user`` schemas cannot redirect lifecycle DDL or erasure."""

    project_id = uuid4()
    with psycopg.connect(scratch_dsn, autocommit=True) as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS tracebed_owner")
        try:
            conn.execute("SET search_path = tracebed_owner, public")
            create_project_partitions(conn, ProjectId(project_id))
            for parent in ("memory_item", "trace_learning_job", "run_owner"):
                child = f"{parent}_p_{project_id.hex}"
                assert conn.execute("SELECT to_regclass(%s)", (f"public.{child}",)).fetchone() != (None,)
                assert conn.execute(
                    "SELECT to_regclass(%s)", (f"tracebed_owner.{child}",)
                ).fetchone() == (None,)
            renamed_memory = f"renamed_memory_{project_id.hex}"
            renamed_owner = f"renamed_owner_{project_id.hex}"
            conn.execute(
                sql.SQL("ALTER TABLE public.{} RENAME TO {}").format(
                    sql.Identifier(f"memory_item_p_{project_id.hex}"), sql.Identifier(renamed_memory)
                )
            )
            conn.execute(
                sql.SQL("ALTER TABLE public.{} RENAME TO {}").format(
                    sql.Identifier(f"run_owner_p_{project_id.hex}"), sql.Identifier(renamed_owner)
                )
            )
            conn.execute(
                sql.SQL("CREATE TABLE tracebed_owner.{} (sentinel integer)").format(
                    sql.Identifier(f"memory_item_p_{project_id.hex}")
                )
            )
            ensure_schema_current(conn)
            drop_project(conn, ProjectId(project_id))
            for parent in ("trace_learning_job",):
                child = f"{parent}_p_{project_id.hex}"
                assert conn.execute("SELECT to_regclass(%s)", (f"public.{child}",)).fetchone() == (None,)
            assert conn.execute("SELECT to_regclass(%s)", (f"public.{renamed_memory}",)).fetchone() == (None,)
            assert conn.execute("SELECT to_regclass(%s)", (f"public.{renamed_owner}",)).fetchone() == (None,)
            assert conn.execute(
                "SELECT to_regclass(%s)", (f"tracebed_owner.memory_item_p_{project_id.hex}",)
            ).fetchone() != (None,)
        finally:
            conn.execute("RESET search_path")
            conn.execute("DROP SCHEMA tracebed_owner")


def _api_group_has_grant_option(conn: psycopg.Connection[Any], relation: str) -> bool:
    row = conn.execute(
        "SELECT EXISTS ("
        "SELECT 1 FROM pg_class AS relation "
        "CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS privilege "
        "JOIN pg_roles AS grantee ON grantee.oid = privilege.grantee "
        "WHERE relation.oid = %s::regclass AND grantee.rolname = 'tracebed_api_group' "
        "AND privilege.privilege_type = 'SELECT' AND privilege.is_grantable"
        ")",
        (relation,),
    ).fetchone()
    assert row is not None
    return bool(row[0])


def test_forward_and_bootstrap_refuse_group_grant_option_without_mutation(scratch_dsn: str) -> None:
    """Expected SELECT with GRANT OPTION is delegation, never an allowlisted ACL."""

    _rollback_to_0009(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute("GRANT SELECT ON project TO tracebed_api_group WITH GRANT OPTION")
        conn.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        assert _api_group_has_grant_option(conn, "project")
        with pytest.raises(RuntimeError, match="unsafe access dependencies"):
            bootstrap.ensure_foundation_roles(conn)
        assert _api_group_has_grant_option(conn, "project")


def test_bootstrap_refuses_post_0010_group_grant_option_without_mutation(scratch_dsn: str) -> None:
    with psycopg.connect(scratch_dsn) as conn:
        bootstrap.ensure_foundation_roles(conn)
        conn.execute("GRANT SELECT ON project TO tracebed_api_group WITH GRANT OPTION")
        conn.commit()
        with pytest.raises(RuntimeError, match="unsafe access dependencies"):
            bootstrap.ensure_foundation_roles(conn)
        assert _api_group_has_grant_option(conn, "project")


def test_bootstrap_retries_after_a_preflight_failure_with_its_baseline_grants(
    scratch_dsn: str,
) -> None:
    """A failed 0010 attempt leaves bootstrap's baseline, not a poisoned retry."""

    _rollback_to_0009(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "INSERT INTO work_queue (project_id, topic, payload) VALUES (%s, 'trace_event', '{}'::jsonb)",
            (uuid4(),),
        )
        conn.commit()

    app_password = os.environ.get("TB_APP_ROLE_PASSWORD", "tracebed_app_dev")
    api_password = "authority-bootstrap-api-password"
    worker_password = "authority-bootstrap-worker-password"
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        bootstrap.bootstrap_database(
            scratch_dsn, app_password, api_password, worker_password, "dedicated"
        )
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)

    with psycopg.connect(scratch_dsn) as conn:
        conn.execute("DELETE FROM work_queue")
        conn.commit()
    bootstrap.bootstrap_database(scratch_dsn, app_password, api_password, worker_password, "dedicated")
    assert "0010_authority_foundation" in current_revision(scratch_dsn)


def test_rollback_refuses_unrelated_group_table_or_function_acl_without_erasing_it(
    scratch_dsn: str,
) -> None:
    table_name = f"authority_unrelated_{uuid4().hex}"
    function_name = f"authority_unrelated_{uuid4().hex}"
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(f"CREATE TABLE {table_name} (value integer)")
        conn.execute(f"GRANT SELECT ON {table_name} TO tracebed_api_group")
        conn.execute(
            f"CREATE FUNCTION {function_name}() RETURNS integer LANGUAGE sql AS 'SELECT 1'"
        )
        conn.execute(f"GRANT EXECUTE ON FUNCTION {function_name}() TO tracebed_api_group")
        conn.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        rollback_migrations(scratch_dsn)
    assert "0010_authority_foundation" in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        assert conn.execute(
            "SELECT has_table_privilege('tracebed_api_group', %s, 'SELECT')", (table_name,)
        ).fetchone() == (True,)
        assert conn.execute(
            "SELECT has_function_privilege('tracebed_api_group', %s, 'EXECUTE')",
            (f"{function_name}()",),
        ).fetchone() == (True,)


def test_rollback_refuses_group_create_membership_and_ownership(scratch_dsn: str) -> None:
    member_role = f"authority_member_{uuid4().hex[:16]}"
    table_name = f"authority_owned_{uuid4().hex}"
    with psycopg.connect(scratch_dsn, autocommit=True) as conn:
        conn.execute(f"CREATE ROLE {member_role} LOGIN")
        conn.execute(f"GRANT tracebed_api_group TO {member_role}")
        conn.execute("GRANT CREATE ON SCHEMA public TO tracebed_worker_group")
        conn.execute(f"CREATE TABLE {table_name} (value integer)")
        conn.execute(f"ALTER TABLE {table_name} OWNER TO tracebed_erasure_group")

    try:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            rollback_migrations(scratch_dsn)
        assert "0010_authority_foundation" in current_revision(scratch_dsn)
        with psycopg.connect(scratch_dsn) as conn:
            assert conn.execute(
                "SELECT has_schema_privilege('tracebed_worker_group', 'public', 'CREATE')"
            ).fetchone() == (True,)
            assert conn.execute(
                "SELECT relowner = (SELECT oid FROM pg_roles WHERE rolname = 'tracebed_erasure_group') "
                "FROM pg_class WHERE oid = %s::regclass",
                (table_name,),
            ).fetchone() == (True,)
    finally:
        with psycopg.connect(scratch_dsn, autocommit=True) as conn:
            conn.execute(f"REVOKE tracebed_api_group FROM {member_role}")
            conn.execute(f"DROP ROLE {member_role}")


def test_rollback_refuses_unsafe_foundation_group_attributes(scratch_dsn: str) -> None:
    """Retained deployment roles are validated even though rollback never drops them."""

    with psycopg.connect(scratch_dsn, autocommit=True) as conn:
        conn.execute(
            "ALTER ROLE tracebed_erasure_group LOGIN CREATEROLE BYPASSRLS CONNECTION LIMIT 7"
        )
    try:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            rollback_migrations(scratch_dsn)
        assert "0010_authority_foundation" in current_revision(scratch_dsn)
    finally:
        with psycopg.connect(scratch_dsn, autocommit=True) as conn:
            conn.execute(
                "ALTER ROLE tracebed_erasure_group NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOINHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1"
            )


def test_fresh_full_migration_tree_rolls_back_through_authority_foundation(
    scratch_dsn: str,
) -> None:
    rolled = rollback_migrations(scratch_dsn, all=True)
    assert rolled[0] == "0010_authority_foundation"
    reapplied = apply_migrations(scratch_dsn)
    assert reapplied[-1] == "0010_authority_foundation"


def test_existing_safe_registration_backfills_data_and_makes_rollback_refuse(
    scratch_dsn: str,
) -> None:
    assert rollback_migrations(scratch_dsn) == ["0010_authority_foundation"]
    project_id, principal_id, agent_type_id, run_id = (uuid4(), uuid4(), uuid4(), uuid4())
    partition = f"trace_index_p_{project_id.hex}"
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "INSERT INTO project (project_id, name, status) VALUES (%s, 'authority-upgrade', 'active')",
            (project_id,),
        )
        conn.execute(
            "INSERT INTO principal (principal_id, kind, external_ref) VALUES (%s, 'oidc_sub', %s)",
            (principal_id, f"authority-{principal_id.hex}"),
        )
        conn.execute(
            "INSERT INTO agent_type (agent_type_id, project_id, name) VALUES (%s, %s, 'authority-agent')",
            (agent_type_id, project_id),
        )
        conn.execute(
            "INSERT INTO agent_registration (principal_id, project_id, agent_type_id) VALUES (%s, %s, %s)",
            (principal_id, project_id, agent_type_id),
        )
        conn.execute(
            f"CREATE TABLE {partition} PARTITION OF trace_index FOR VALUES IN ('{project_id}')"
        )
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        conn.execute(
            "INSERT INTO trace_index "
            "(run_id, project_id, agent_type_id, submitter_principal, input_signature_hash, instrumentation_source) "
            "VALUES (%s, %s, %s, %s, %s, 'sdk')",
            (run_id, project_id, agent_type_id, principal_id, b"x" * 32),
        )
        conn.commit()

    assert apply_migrations(scratch_dsn) == ["0010_authority_foundation"]
    with psycopg.connect(scratch_dsn) as conn:
        grant = conn.execute(
            "SELECT role, granted_by FROM principal_grant WHERE project_id = %s", (project_id,)
        ).fetchone()
        assert grant == ("data", None)
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        owner = conn.execute(
            "SELECT principal_id, agent_type_id, origin FROM run_owner WHERE project_id = %s", (project_id,)
        ).fetchone()
        assert owner == (principal_id, agent_type_id, "trace")
        child = f"run_owner_p_{project_id.hex}"
        child_security = conn.execute(
            "SELECT c.relforcerowsecurity, EXISTS ("
            "SELECT 1 FROM pg_policy AS policy WHERE policy.polrelid = c.oid"
            ") FROM pg_class AS c WHERE c.relname = %s",
            (child,),
        ).fetchone()
        assert child_security == (True, True)
        index = conn.execute(
            "SELECT 1 FROM pg_indexes WHERE indexname = %s", (f"{child}_owner",)
        ).fetchone()
        assert index == (1,)
        privileges = conn.execute(
            "SELECT "
            "has_table_privilege('tracebed_api_group', 'work_queue', 'INSERT'), "
            "has_table_privilege('tracebed_worker_group', 'work_queue', 'UPDATE'), "
            "has_table_privilege('tracebed_worker_group', 'dead_letter', 'INSERT'), "
            "has_table_privilege('tracebed_erasure_group', 'work_queue', 'SELECT')"
        ).fetchone()
        assert privileges == (True, True, True, False)
        conn.execute("SELECT set_config('tracebed.project_id', '', true)")
        conn.execute("SET ROLE tracebed_worker_group")
        unscoped = conn.execute("SELECT count(*) FROM run_owner").fetchone()
        assert unscoped == (0,)
        conn.execute("RESET ROLE")
        conn.execute("UPDATE project SET status = 'suspended' WHERE project_id = %s", (project_id,))
        conn.execute("UPDATE project SET status = 'active' WHERE project_id = %s", (project_id,))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("DELETE FROM principal WHERE principal_id = %s", (principal_id,))
        conn.rollback()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        rollback_migrations(scratch_dsn)
    assert "0010_authority_foundation" in current_revision(scratch_dsn)


def test_nonempty_legacy_queue_refuses_without_marking_0010(scratch_dsn: str) -> None:
    _rollback_to_0009(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "INSERT INTO work_queue (project_id, topic, payload) VALUES (%s, 'trace_event', '{}'::jsonb)",
            (uuid4(),),
        )
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)

    with psycopg.connect(scratch_dsn) as conn:
        assert conn.execute("SELECT to_regclass('public.principal_grant')").fetchone() == (None,)


def test_preflight_rejects_invalid_legacy_principal_revocation_timestamp(scratch_dsn: str) -> None:
    _rollback_to_0009(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        principal_id = uuid4()
        conn.execute(
            "INSERT INTO principal (principal_id, kind, external_ref, created_at, revoked_at) "
            "VALUES (%s, 'oidc_sub', %s, now(), now() - interval '1 second')",
            (principal_id, f"invalid-revocation-{principal_id.hex}"),
        )
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)


def test_preflight_rejects_legacy_registry_and_running_lease_shapes(scratch_dsn: str) -> None:
    _rollback_to_0009(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        first_project, first_principal, _ = _legacy_identity(conn)
        _, _, second_agent_type = _legacy_identity(conn)
        conn.execute(
            "UPDATE agent_registration SET agent_type_id = %s WHERE principal_id = %s",
            (second_agent_type, first_principal),
        )
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)

    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "UPDATE agent_registration SET agent_type_id = ("
            "SELECT agent_type_id FROM agent_type WHERE project_id = %s) WHERE principal_id = %s",
            (first_project, first_principal),
        )
        conn.execute("UPDATE project SET deleted_at = now() WHERE project_id = %s", (first_project,))
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)


def test_preflight_rejects_running_lease_and_deleted_project_leftover(scratch_dsn: str) -> None:
    _rollback_to_0009(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        project_id, _, _ = _legacy_identity(conn)
        job_partition = f"trace_learning_job_p_{project_id.hex}"
        conn.execute(
            f"CREATE TABLE {job_partition} PARTITION OF trace_learning_job FOR VALUES IN ('{project_id}')"
        )
        run_id = uuid4()
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        conn.execute(
            "INSERT INTO trace_learning_job "
            "(project_id, run_id, pipeline, pipeline_version, state, attempts, max_attempts, available_at, trace_ended_at, schedule_source, scheduled_at, updated_at) "
            "VALUES (%s, %s, 'tier_a', 1, 'pending', 0, 2, now(), now(), 'live', now(), now())",
            (project_id, run_id),
        )
        conn.execute(
            "UPDATE trace_learning_job SET state = 'running', attempts = 1, lease_token = %s, "
            "lease_owner = 'authority-preflight', lease_expires_at = now() + interval '1 minute', "
            "first_started_at = now() WHERE project_id = %s AND run_id = %s",
            (uuid4(), project_id, run_id),
        )
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        assert conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'trace_learning_job'::regclass"
        ).fetchone() == (True, True)

    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "UPDATE trace_learning_job SET state = 'retry', lease_token = NULL, lease_owner = NULL, "
            "lease_expires_at = NULL, available_at = now(), last_error_code = 'lease_expired' "
            "WHERE project_id = %s AND run_id = %s",
            (project_id, run_id),
        )
        deleted_id = uuid4()
        conn.execute(
            "INSERT INTO project (project_id, name, status, deleted_at) VALUES (%s, %s, 'deleted', now())",
            (deleted_id, f"deleted-leftover-{deleted_id.hex}"),
        )
        _create_trace_partition(conn, deleted_id)
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        assert conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'trace_index'::regclass"
        ).fetchone() == (True, True)


def test_preflight_refuses_orphan_running_job_and_orphan_trace_before_backfill(
    scratch_dsn: str,
) -> None:
    """Global preflights cover UUIDs not represented in the project registry."""

    _rollback_to_0009(scratch_dsn)
    job_project, job_run = uuid4(), uuid4()
    trace_project, trace_run = uuid4(), uuid4()
    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            f"CREATE TABLE trace_learning_job_p_{job_project.hex} "
            f"PARTITION OF trace_learning_job FOR VALUES IN ('{job_project}')"
        )
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(job_project),))
        conn.execute(
            "INSERT INTO trace_learning_job "
            "(project_id, run_id, pipeline, pipeline_version, state, attempts, max_attempts, "
            "available_at, trace_ended_at, schedule_source, scheduled_at, updated_at) "
            "VALUES (%s, %s, 'tier_a', 1, 'pending', 0, 2, now(), now(), 'live', now(), now())",
            (job_project, job_run),
        )
        conn.execute(
            "UPDATE trace_learning_job SET state = 'running', attempts = 1, lease_token = %s, "
            "lease_owner = 'orphan-preflight', lease_expires_at = now() + interval '1 minute', "
            "first_started_at = now() WHERE project_id = %s AND run_id = %s",
            (uuid4(), job_project, job_run),
        )
        conn.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)

    with psycopg.connect(scratch_dsn) as conn:
        assert conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'trace_learning_job'::regclass"
        ).fetchone() == (True, True)

    with psycopg.connect(scratch_dsn) as conn:
        conn.execute(
            "UPDATE trace_learning_job SET state = 'retry', lease_token = NULL, lease_owner = NULL, "
            "lease_expires_at = NULL, available_at = now(), last_error_code = 'lease_expired' "
            "WHERE project_id = %s AND run_id = %s",
            (job_project, job_run),
        )
        _create_trace_partition(conn, trace_project)
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(trace_project),))
        conn.execute(
            "INSERT INTO trace_index "
            "(run_id, project_id, agent_type_id, submitter_principal, input_signature_hash, instrumentation_source) "
            "VALUES (%s, %s, %s, %s, %s, 'sdk')",
            (trace_run, trace_project, uuid4(), uuid4(), b"orphan-trace".ljust(32, b"x")),
        )
        conn.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        apply_migrations(scratch_dsn)
    assert "0010_authority_foundation" not in current_revision(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        assert conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'trace_index'::regclass"
        ).fetchone() == (True, True)


def test_backfill_excludes_deleted_revoked_and_future_registrations(scratch_dsn: str) -> None:
    _rollback_to_0009(scratch_dsn)
    with psycopg.connect(scratch_dsn) as conn:
        active = _legacy_identity(conn)
        suspended = _legacy_identity(conn, status="suspended")
        deleted = _legacy_identity(conn, status="deleted")
        revoked = _legacy_identity(conn, revoked_principal=True)
        conn.commit()

    assert apply_migrations(scratch_dsn) == ["0010_authority_foundation"]
    with psycopg.connect(scratch_dsn) as conn:
        rows = conn.execute(
            "SELECT project_id, principal_id FROM principal_grant WHERE role = 'data' ORDER BY project_id"
        ).fetchall()
        assert set(rows) == {(active[0], active[1]), (suspended[0], suspended[1])}
        assert (deleted[0], deleted[1]) not in rows
        assert (revoked[0], revoked[1]) not in rows

        future_project, future_principal, _ = _legacy_identity(conn)
        assert conn.execute(
            "SELECT count(*) FROM principal_grant WHERE project_id = %s AND principal_id = %s",
            (future_project, future_principal),
        ).fetchone() == (0,)


def test_registry_owner_mutations_are_rejected_and_run_owner_is_fail_closed(
    scratch_dsn: str,
) -> None:
    _rollback_to_0009(scratch_dsn)
    run_id = uuid4()
    with psycopg.connect(scratch_dsn) as conn:
        project_id, principal_id, agent_type_id = _legacy_identity(conn)
        _create_trace_partition(conn, project_id)
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        conn.execute(
            "INSERT INTO trace_index "
            "(run_id, project_id, agent_type_id, submitter_principal, input_signature_hash, instrumentation_source) "
            "VALUES (%s, %s, %s, %s, %s, 'sdk')",
            (run_id, project_id, agent_type_id, principal_id, b"x" * 32),
        )
        conn.commit()
    apply_migrations(scratch_dsn)

    with psycopg.connect(scratch_dsn) as conn:
        conn.execute("SET ROLE tracebed_app")
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        assert conn.execute("SELECT count(*) FROM run_owner").fetchone() == (1,)
        conn.execute("SELECT set_config('tracebed.project_id', '', true)")
        assert conn.execute("SELECT count(*) FROM run_owner").fetchone() == (0,)
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(uuid4()),))
        assert conn.execute("SELECT count(*) FROM run_owner").fetchone() == (0,)
        conn.execute("RESET ROLE")
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))

        _expect_check_violation(
            conn, "UPDATE project SET project_id = %s WHERE project_id = %s", (uuid4(), project_id)
        )
        _expect_check_violation(
            conn,
            "UPDATE project SET provisioning_key_hash = %s WHERE project_id = %s",
            ("p" * 64, project_id),
        )
        _expect_check_violation(
            conn, "UPDATE project SET status = 'deleted' WHERE project_id = %s", (project_id,)
        )
        _expect_check_violation(
            conn,
            "UPDATE principal SET external_ref = 'mutated' WHERE principal_id = %s",
            (principal_id,),
        )
        _expect_check_violation(
            conn, "DELETE FROM principal WHERE principal_id = %s", (principal_id,)
        )
        _expect_check_violation(
            conn,
            "INSERT INTO principal (principal_id, kind, external_ref, revoked_at) "
            "VALUES (%s, 'oidc_sub', %s, now())",
            (uuid4(), f"pre-revoked-{uuid4().hex}"),
        )
        _expect_check_violation(
            conn, "UPDATE agent_type SET name = 'mutated' WHERE agent_type_id = %s", (agent_type_id,)
        )
        _expect_check_violation(
            conn, "DELETE FROM agent_type WHERE agent_type_id = %s", (agent_type_id,)
        )
        assert conn.execute(
            "INSERT INTO agent_type (agent_type_id, project_id, name) VALUES (%s, %s, %s) "
            "ON CONFLICT (project_id, name) DO UPDATE SET name = EXCLUDED.name RETURNING agent_type_id",
            (agent_type_id, project_id, f"agent-{agent_type_id.hex}"),
        ).fetchone() == (agent_type_id,)
        _expect_check_violation(
            conn,
            "UPDATE agent_registration SET agent_type_id = %s WHERE principal_id = %s",
            (uuid4(), principal_id),
        )
        _expect_check_violation(
            conn, "DELETE FROM agent_registration WHERE principal_id = %s", (principal_id,)
        )
        grant_id = conn.execute("SELECT grant_id FROM principal_grant WHERE project_id = %s", (project_id,)).fetchone()[0]
        _expect_check_violation(
            conn, "UPDATE principal_grant SET role = 'admin' WHERE grant_id = %s", (grant_id,)
        )
        _expect_check_violation(conn, "DELETE FROM principal_grant WHERE grant_id = %s", (grant_id,))
        _expect_check_violation(
            conn, "UPDATE run_owner SET origin = 'retrieve' WHERE project_id = %s AND run_id = %s", (project_id, run_id)
        )
        _expect_check_violation(
            conn, "DELETE FROM run_owner WHERE project_id = %s AND run_id = %s", (project_id, run_id)
        )

        conn.execute("UPDATE agent_registration SET revoked_at = now() WHERE principal_id = %s", (principal_id,))
        _expect_check_violation(
            conn, "UPDATE agent_registration SET revoked_at = NULL WHERE principal_id = %s", (principal_id,)
        )
        _expect_check_violation(
            conn,
            "UPDATE agent_registration SET revoked_at = now() + interval '1 second' WHERE principal_id = %s",
            (principal_id,),
        )
        conn.execute("UPDATE principal_grant SET revoked_at = now() WHERE grant_id = %s", (grant_id,))
        _expect_check_violation(
            conn, "UPDATE principal_grant SET revoked_at = NULL WHERE grant_id = %s", (grant_id,)
        )
        _expect_check_violation(
            conn,
            "UPDATE principal_grant SET revoked_at = now() + interval '1 second' WHERE grant_id = %s",
            (grant_id,),
        )
        conn.execute("UPDATE principal SET revoked_at = now() WHERE principal_id = %s", (principal_id,))
        _expect_check_violation(
            conn, "UPDATE principal SET revoked_at = NULL WHERE principal_id = %s", (principal_id,)
        )
        _expect_check_violation(
            conn,
            "UPDATE principal SET revoked_at = now() + interval '1 second' WHERE principal_id = %s",
            (principal_id,),
        )
        conn.rollback()


def test_versioned_queue_outcome_shapes_and_subject_digest_validation(scratch_dsn: str) -> None:
    with psycopg.connect(scratch_dsn) as conn:
        project_id, principal_id, agent_type_id = _legacy_identity(conn)
        ensure_schema_current(conn)
        run_id, grant_id = uuid4(), uuid4()
        digest_a, digest_b = b"a" * 32, b"b" * 32
        conn.execute("SELECT set_config('tracebed.project_id', %s, true)", (str(project_id),))
        assert conn.execute(
            "INSERT INTO work_queue (project_id, topic, payload) VALUES (%s, 'trace_event', '{}'::jsonb) "
            "RETURNING authority_version, run_id, subject_digests",
            (project_id,),
        ).fetchone() == (0, None, [])
        _expect_check_violation(
            conn, "UPDATE work_queue SET run_id = %s WHERE project_id = %s AND authority_version = 0", (run_id, project_id)
        )
        conn.execute("SAVEPOINT authority_version_null")
        with pytest.raises(psycopg.errors.NotNullViolation):
            conn.execute(
                "INSERT INTO work_queue (project_id, topic, payload, authority_version) "
                "VALUES (%s, 'trace_event', '{}'::jsonb, NULL)",
                (project_id,),
            )
        conn.execute("ROLLBACK TO SAVEPOINT authority_version_null")
        conn.execute("RELEASE SAVEPOINT authority_version_null")

        common = (project_id, run_id, principal_id, agent_type_id, grant_id, principal_id, agent_type_id)
        conn.execute(
            "INSERT INTO work_queue (project_id, topic, payload, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role, run_owner_principal_id, run_owner_agent_type_id, subject_digests) "
            "VALUES (%s, 'trace_event', '{}'::jsonb, 1, %s, %s, %s, %s, 'data', %s, %s, %s)",
            (*common, [digest_a, digest_b]),
        )
        conn.execute(
            "INSERT INTO work_queue (project_id, topic, payload, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, 'memory_proposal', '{}'::jsonb, 1, %s, %s, %s, %s, 'data', %s, %s)",
            common,
        )
        conn.execute(
            "INSERT INTO dead_letter (id, project_id, topic, payload, priority, available_at, attempts, max_attempts, created_at, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role, feedback_source, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (9001, %s, 'outcome_event', '{}'::jsonb, 1, now(), 0, 1, now(), 1, %s, %s, %s, %s, 'feedback', 'verdict', %s, %s)",
            common,
        )
        conn.execute(
            "INSERT INTO outcome_event (event_id, run_id, project_id, principal_id, adapter, r, authority_version, source_agent_type_id, source_grant_id, feedback_source, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, %s, %s, %s, 'verdict', 1.0, 1, %s, %s, 'verdict', %s, %s)",
            (uuid4(), run_id, project_id, principal_id, agent_type_id, grant_id, principal_id, agent_type_id),
        )
        _expect_check_violation(
            conn,
            "INSERT INTO work_queue (project_id, topic, payload, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, 'trace_event', '{}'::jsonb, 1, %s, %s, %s, %s, 'feedback', %s, %s)",
            common,
        )
        _expect_check_violation(
            conn,
            "INSERT INTO work_queue (project_id, topic, payload, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, 'trace_event', '{}'::jsonb, 1, %s, %s, %s, %s, 'data', %s, %s)",
            (project_id, run_id, principal_id, agent_type_id, grant_id, uuid4(), agent_type_id),
        )
        _expect_check_violation(
            conn,
            "INSERT INTO work_queue (project_id, topic, payload, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role) "
            "VALUES (%s, 'trace_event', '{}'::jsonb, 1, %s, %s, %s, %s, 'data')",
            (project_id, run_id, principal_id, agent_type_id, grant_id),
        )
        _expect_check_violation(
            conn,
            "INSERT INTO work_queue (project_id, topic, payload, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, 'outcome_event', '{}'::jsonb, 1, %s, %s, %s, %s, 'feedback', %s, %s)",
            common,
        )
        _expect_check_violation(
            conn,
            "INSERT INTO dead_letter (id, project_id, topic, payload, priority, available_at, attempts, max_attempts, created_at, authority_version, run_id, source_principal_id, source_agent_type_id, source_grant_id, required_role, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (9002, %s, 'outcome_event', '{}'::jsonb, 1, now(), 0, 1, now(), 1, %s, %s, %s, %s, 'feedback', %s, %s)",
            common,
        )
        _expect_check_violation(
            conn,
            "INSERT INTO outcome_event (event_id, run_id, project_id, principal_id, adapter, r, authority_version, source_agent_type_id, source_grant_id, feedback_source, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, %s, %s, %s, 'implicit', 1.0, 1, %s, %s, 'verdict', %s, %s)",
            (uuid4(), run_id, project_id, principal_id, agent_type_id, grant_id, principal_id, agent_type_id),
        )
        _expect_check_violation(
            conn,
            "INSERT INTO outcome_event (event_id, run_id, project_id, principal_id, adapter, r, authority_version, source_agent_type_id, source_grant_id, run_owner_principal_id, run_owner_agent_type_id) "
            "VALUES (%s, %s, %s, %s, 'verdict', 1.0, 1, %s, %s, %s, %s)",
            (uuid4(), run_id, project_id, principal_id, agent_type_id, grant_id, principal_id, agent_type_id),
        )
        matrix = conn.execute(
            "SELECT subject_digests_are_valid(ARRAY[]::bytea[]), "
            "subject_digests_are_valid(ARRAY[%s, %s]), "
            "subject_digests_are_valid(ARRAY[%s, %s]), "
            "subject_digests_are_valid(ARRAY[%s, %s]), "
            "subject_digests_are_valid(ARRAY[%s]), "
            "subject_digests_are_valid(ARRAY[%s, NULL::bytea]), "
            "subject_digests_are_valid(array_fill(%s::bytea, ARRAY[65])), "
            "subject_digests_are_valid(ARRAY[[%s]])",
            (
                digest_a,
                digest_b,
                digest_b,
                digest_a,
                digest_a,
                digest_a,
                b"x" * 31,
                digest_a,
                digest_a,
                digest_a,
            ),
        ).fetchone()
        assert matrix == (True, True, False, False, False, False, False, False)


def test_partition_repair_lifecycle_filter_and_role_privilege_matrix(scratch_dsn: str) -> None:
    with psycopg.connect(scratch_dsn) as conn:
        active, _, _ = _legacy_identity(conn)
        suspended, _, _ = _legacy_identity(conn)
        deleting, _, _ = _legacy_identity(conn)
        deleted, _, _ = _legacy_identity(conn)
        conn.execute("UPDATE project SET status = 'suspended' WHERE project_id = %s", (suspended,))
        conn.execute("UPDATE project SET status = 'deleting' WHERE project_id = %s", (deleting,))
        conn.execute("UPDATE project SET status = 'deleting' WHERE project_id = %s", (deleted,))
        conn.execute("UPDATE project SET status = 'deleted' WHERE project_id = %s", (deleted,))
        server_timestamp, _, _ = _legacy_identity(conn)
        conn.execute("UPDATE project SET status = 'deleting' WHERE project_id = %s", (server_timestamp,))
        assert conn.execute(
            "UPDATE project SET status = 'deleted', deleted_at = timestamptz '2000-01-01 00:00:00+00' "
            "WHERE project_id = %s RETURNING deleted_at > timestamptz '2020-01-01 00:00:00+00'",
            (server_timestamp,),
        ).fetchone() == (True,)
        ensure_schema_current(conn)
        relations = {
            project_id: conn.execute(
                "SELECT to_regclass(%s)", (f"run_owner_p_{project_id.hex}",)
            ).fetchone()[0]
            for project_id in (active, suspended, deleting, deleted, server_timestamp)
        }
        assert relations[active] is not None and relations[suspended] is not None
        assert relations[deleting] is None and relations[deleted] is None and relations[server_timestamp] is None
        conn.execute(f"GRANT DELETE ON run_owner_p_{active.hex} TO tracebed_erasure_group")
        ensure_schema_current(conn)
        matrix = conn.execute(
            "SELECT "
            "has_database_privilege('tracebed_api_group', current_database(), 'CONNECT'), "
            "has_schema_privilege('tracebed_erasure_group', 'public', 'USAGE'), "
            "has_table_privilege('tracebed_api_group', 'principal_grant', 'SELECT'), "
            "has_table_privilege('tracebed_api_group', 'principal_grant', 'INSERT'), "
            "has_table_privilege('tracebed_worker_group', 'run_owner', 'SELECT'), "
            "has_table_privilege('tracebed_worker_group', 'run_owner', 'INSERT'), "
            "has_table_privilege('tracebed_api_group', 'work_queue', 'INSERT'), "
            "has_sequence_privilege('tracebed_api_group', 'work_queue_id_seq', 'USAGE'), "
            "has_table_privilege('tracebed_worker_group', 'work_queue', 'UPDATE'), "
            "has_table_privilege('tracebed_worker_group', 'dead_letter', 'INSERT'), "
            "has_table_privilege('tracebed_erasure_group', 'work_queue', 'SELECT'), "
            "has_table_privilege('tracebed_erasure_group', 'run_owner', 'SELECT'), "
            "has_table_privilege('tracebed_erasure_group', %s, 'DELETE'), "
            "has_table_privilege('tracebed_app', 'principal_grant', 'INSERT'), "
            "has_table_privilege('tracebed_app', 'run_owner', 'INSERT'), "
            "has_table_privilege('tracebed_app', 'run_owner', 'UPDATE'), "
            "has_table_privilege('tracebed_api_group', 'memory_item', 'SELECT'), "
            "has_table_privilege('tracebed_worker_group', 'memory_item', 'SELECT'), "
            "has_table_privilege('tracebed_api_group', 'project', 'UPDATE'), "
            "has_table_privilege('tracebed_worker_group', 'principal_grant', 'UPDATE'), "
            "has_function_privilege('tracebed_erasure_group', 'subject_digests_are_valid(bytea[])', 'EXECUTE'), "
            "NOT EXISTS ("
            "SELECT 1 FROM pg_proc AS function "
            "CROSS JOIN LATERAL aclexplode(COALESCE(function.proacl, acldefault('f', function.proowner))) AS privilege "
            "WHERE function.oid = 'subject_digests_are_valid(bytea[])'::regprocedure "
            "AND privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'"
            ")",
            (f"run_owner_p_{active.hex}",),
        ).fetchone()
        assert matrix == (
            True,
            True,
            True,
            False,
            True,
            False,
            True,
            True,
            True,
            True,
            False,
            False,
            False,
            False,
            True,
            False,
            False,
            False,
            False,
            False,
            False,
            True,
        )
