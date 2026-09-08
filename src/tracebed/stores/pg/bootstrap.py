"""Owner-run, idempotent bootstrap for a Tracebed database deployment.

This is deliberately separate from migrations.  The application role must
exist with RLS-safe attributes *before* migration SQL grants it access, while
migrations and per-project partition repair still run as the database owner.
The command takes its owner DSN and app password from environment variables so
neither is placed in command-line arguments or emitted in diagnostics.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime
from typing import Any, Final, Literal, NamedTuple
from urllib.parse import SplitResult, parse_qsl, quote, urlencode, urlunsplit
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from tracebed.domain.errors import ConfigError
from tracebed.stores.pg.authority_dsn import parse_authority_migration_url, trusted_authority_dsn
from tracebed.stores.pg.hba import (
    COMPOSE_V1_PROFILE,
    HBA_PROFILE_ENV,
    LEGACY_INGRESS_ENV,
    attest_compose_v1_hba,
    require_compose_v1_profile,
)
from tracebed.stores.pg.migrate import apply_migrations, rollback_migrations
from tracebed.stores.pg.partitions import ensure_schema_current

__all__ = [
    "API_ROLE",
    "APP_ROLE",
    "BOOTSTRAP_LOCK_KEY",
    "ERASURE_ROLE",
    "WORKER_ROLE",
    "bootstrap_database",
    "ensure_app_role",
    "ensure_foundation_roles",
    "ensure_split_roles_pre_activation",
    "main",
    "quarantine_authority_cutover_for_rollback",
    "quarantine_erasure_cutover_for_rollback",
    "quarantine_legacy_app_for_cutover",
]

APP_ROLE: Final = "tracebed_app"
"""Fixed, non-configurable application role name used by all RLS grants."""

FOUNDATION_GROUP_ROLES: Final[tuple[str, ...]] = (
    "tracebed_api_group",
    "tracebed_worker_group",
    "tracebed_erasure_group",
)
"""NOLOGIN roles introduced by 0010; credential-bearing roles join them later."""

BOOTSTRAP_LOCK_KEY: Final = 8_127_422_187_041_237
"""Fixed session advisory-lock key for role/migration/partition bootstrap."""

_OWNER_DSN_ENV: Final = "TB_BOOTSTRAP_PG_DSN"
_APP_PASSWORD_ENV: Final = "TB_APP_PASSWORD"  # noqa: S105 - environment-variable name only
_API_PASSWORD_ENV: Final = "TB_API_DB_PASSWORD"  # noqa: S105 - environment-variable name only
_WORKER_PASSWORD_ENV: Final = "TB_WORKER_DB_PASSWORD"  # noqa: S105 - environment-variable name only
_ERASURE_PASSWORD_ENV: Final = "TB_ERASURE_DB_PASSWORD"  # noqa: S105 - environment-variable name only
_CLUSTER_SCOPE_ENV: Final = "TB_PG_CLUSTER_SCOPE"
_BOOTSTRAP_ACTION_ENV: Final = "TB_DB_BOOTSTRAP_ACTION"
_BOOTSTRAP_APPLY_ACTION: Final = "apply"
_BOOTSTRAP_ROLLBACK_ACTION: Final = "rollback"
_BOOTSTRAP_ROLLBACK_0011_ACTION: Final = "rollback-0011"
_BOOTSTRAP_CUTOVER_0012_ACTION: Final = "cutover-0012"
_BOOTSTRAP_CUTOVER_0012_CLOSED_ACTION: Final = "cutover-0012-closed"
_BOOTSTRAP_CUTOVER_0013_ACTION: Final = "cutover-0013"
_BOOTSTRAP_ROLLBACK_0012_ACTION: Final = "rollback-0012"
_BOOTSTRAP_ROLLBACK_0013_ACTION: Final = "rollback-0013"
_BOOTSTRAP_ADMISSION_CLOSE_ACTION: Final = "admission-close"
_BOOTSTRAP_ADMISSION_OPEN_ACTION: Final = "admission-open"
_BOOTSTRAP_RUNTIME_DRAIN_ASSERT_ACTION: Final = "runtime-drain-assert"
_BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION: Final = "admission-assert-closed"
_BOOTSTRAP_ERASURE_DRAIN_ASSERT_ACTION: Final = "erasure-drain-assert"
_BOOTSTRAP_START_PREFLIGHT_ACTION: Final = "start-preflight"
_BOOTSTRAP_ROLLBACK_RECOVERY_PREFLIGHT_ACTION: Final = "rollback-recovery-preflight"
_BOOTSTRAP_ROLLBACK_REFUSAL_RECOVERY_PREFLIGHT_ACTION: Final = (
    "rollback-refusal-recovery-preflight"
)
_DEDICATED_CLUSTER_SCOPE: Final = "dedicated"
_INGRESS_QUARANTINED_GUC: Final = "tracebed.ingress_quarantined"
_CREDENTIAL_PROBE_PREFIX: Final = "tracebed_bootstrap_probe_"
_CREDENTIAL_PROBE_LIFETIME_SECONDS: Final = 300
_CREDENTIAL_PROBE_COMMENT: Final = "tracebed credential probe v1"
_CREDENTIAL_PROBE_NAME_RE: Final = re.compile(r"\Atracebed_bootstrap_probe_[0-9a-f]{32}\Z")
_COMPOSE_ADMIN_HOST: Final = "postgres-admin"
_COMPOSE_API_HOST: Final = "postgres-api"
_COMPOSE_WORKER_HOST: Final = "postgres-worker"
_COMPOSE_PROBE_HOST: Final = "postgres-probe"
_COMPOSE_ERASURE_HOST: Final = "postgres-erasure"
_COMPOSE_ADMIN_POSTGRES_IP: Final = "10.77.10.2"
_COMPOSE_ADMIN_CLIENT_IP: Final = "10.77.10.3"
API_ROLE: Final = "tracebed_api"
WORKER_ROLE: Final = "tracebed_worker"
ERASURE_ROLE: Final = "tracebed_erasure"
_SPLIT_ROLES: Final[tuple[tuple[str, str], ...]] = (
    (API_ROLE, "tracebed_api_group"),
    (WORKER_ROLE, "tracebed_worker_group"),
)
_ROLE_EXISTS_SQL: Final = "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)"
_ROLE_STATE_SQL: Final = """
SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
       role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
       auth.rolpassword IS NULL, auth.rolvaliduntil IS NULL
FROM pg_roles AS role
JOIN pg_authid AS auth ON auth.oid = role.oid
WHERE role.rolname = %s
"""
_ROLE_MEMBERSHIPS_SQL: Final = """
SELECT granted.rolname
FROM pg_auth_members AS membership
JOIN pg_roles AS granted ON granted.oid = membership.roleid
JOIN pg_roles AS member ON member.oid = membership.member
WHERE member.rolname = %s
ORDER BY granted.rolname
"""
_ROLE_MEMBERSHIP_COUNT_SQL: Final = """
SELECT count(*)
FROM pg_auth_members AS membership
JOIN pg_roles AS member ON member.oid = membership.member
WHERE member.rolname = %s
"""
_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL: Final = """
SELECT count(*)
FROM pg_auth_members AS membership
JOIN pg_roles AS group_role
  ON group_role.oid = membership.member OR group_role.oid = membership.roleid
WHERE group_role.rolname = %s
"""
_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL: Final = """
SELECT count(*)
FROM (
    SELECT datdba AS owner_oid FROM pg_database
    UNION ALL SELECT spcowner FROM pg_tablespace
    UNION ALL SELECT nspowner FROM pg_namespace
    UNION ALL SELECT relowner FROM pg_class
    UNION ALL SELECT proowner FROM pg_proc
    UNION ALL SELECT typowner FROM pg_type
    UNION ALL SELECT extowner FROM pg_extension
    UNION ALL SELECT lanowner FROM pg_language
    UNION ALL SELECT collowner FROM pg_collation
    UNION ALL SELECT conowner FROM pg_conversion
    UNION ALL SELECT oprowner FROM pg_operator
    UNION ALL SELECT opcowner FROM pg_opclass
    UNION ALL SELECT opfowner FROM pg_opfamily
    UNION ALL SELECT cfgowner FROM pg_ts_config
    UNION ALL SELECT dictowner FROM pg_ts_dict
    UNION ALL SELECT fdwowner FROM pg_foreign_data_wrapper
    UNION ALL SELECT srvowner FROM pg_foreign_server
    UNION ALL SELECT evtowner FROM pg_event_trigger
    UNION ALL SELECT pubowner FROM pg_publication
    UNION ALL SELECT subowner FROM pg_subscription
    UNION ALL SELECT lomowner FROM pg_largeobject_metadata
    UNION ALL SELECT stxowner FROM pg_statistic_ext
    UNION ALL SELECT defaclrole FROM pg_default_acl
) AS ownership
JOIN pg_roles AS owner ON owner.oid = ownership.owner_oid
WHERE owner.rolname = %s
"""
_FOUNDATION_ROLE_RESIDUAL_DEPENDENCY_COUNT_SQL: Final = """
SELECT count(*)
FROM pg_shdepend AS dependency
JOIN pg_roles AS role ON role.oid = dependency.refobjid
WHERE role.rolname = %s
  AND dependency.refclassid = 'pg_authid'::regclass
  AND dependency.deptype IN ('a', 'i', 'r', 't', 'o')
"""
_FOUNDATION_ROLE_NON_ACL_DEPENDENCY_COUNT_SQL: Final = """
SELECT count(*)
FROM pg_shdepend AS dependency
JOIN pg_roles AS role ON role.oid = dependency.refobjid
WHERE role.rolname = %s
  AND dependency.refclassid = 'pg_authid'::regclass
  AND dependency.deptype IN ('i', 'r', 't', 'o')
"""
_FOUNDATION_ROLE_UNSAFE_ACL_COUNT_SQL: Final = """
SELECT count(*)
FROM (
    SELECT database.datdba AS owner_oid, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_database AS database
      CROSS JOIN LATERAL aclexplode(
          COALESCE(database.datacl, acldefault('d', database.datdba))
      ) AS privilege
    UNION ALL
    SELECT tablespace.spcowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_tablespace AS tablespace
      CROSS JOIN LATERAL aclexplode(
          COALESCE(tablespace.spcacl, acldefault('t', tablespace.spcowner))
      ) AS privilege
    UNION ALL
    SELECT namespace.nspowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_namespace AS namespace
      CROSS JOIN LATERAL aclexplode(
          COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
      ) AS privilege
    UNION ALL
    SELECT relation.relowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_class AS relation
      CROSS JOIN LATERAL aclexplode(
          COALESCE(relation.relacl, acldefault('r', relation.relowner))
      ) AS privilege
    UNION ALL
    SELECT routine.proowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_proc AS routine
      CROSS JOIN LATERAL aclexplode(
          COALESCE(routine.proacl, acldefault('f', routine.proowner))
      ) AS privilege
    UNION ALL
    SELECT type.typowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_type AS type
      CROSS JOIN LATERAL aclexplode(
          COALESCE(type.typacl, acldefault('T', type.typowner))
      ) AS privilege
    UNION ALL
    SELECT language.lanowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_language AS language
      CROSS JOIN LATERAL aclexplode(
          COALESCE(language.lanacl, acldefault('l', language.lanowner))
      ) AS privilege
    UNION ALL
    SELECT wrapper.fdwowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_foreign_data_wrapper AS wrapper
      CROSS JOIN LATERAL aclexplode(
          COALESCE(wrapper.fdwacl, acldefault('F', wrapper.fdwowner))
      ) AS privilege
    UNION ALL
    SELECT server.srvowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_foreign_server AS server
      CROSS JOIN LATERAL aclexplode(
          COALESCE(server.srvacl, acldefault('S', server.srvowner))
      ) AS privilege
    UNION ALL
    SELECT metadata.lomowner, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_largeobject_metadata AS metadata
      CROSS JOIN LATERAL aclexplode(
          COALESCE(metadata.lomacl, acldefault('L', metadata.lomowner))
      ) AS privilege
    UNION ALL
    SELECT default_acl.defaclrole, privilege.grantee, privilege.grantor,
           privilege.is_grantable
      FROM pg_default_acl AS default_acl
      CROSS JOIN LATERAL aclexplode(default_acl.defaclacl) AS privilege
) AS acl_entry
JOIN pg_roles AS grantee ON grantee.oid = acl_entry.grantee
WHERE grantee.rolname = %s
  AND (acl_entry.is_grantable OR acl_entry.grantor IS DISTINCT FROM acl_entry.owner_oid)
"""
_FOUNDATION_POST_0010_SQL: Final = "SELECT to_regclass('public.principal_grant') IS NOT NULL"
_CUTOVER_PRESENT_SQL: Final = "SELECT to_regclass('public.authority_cutover_state') IS NOT NULL"
_ERASURE_CUTOVER_PRESENT_SQL: Final = "SELECT to_regclass('public.erasure_cutover_state') IS NOT NULL"
_ERASURE_DEPLOYMENT_PRESENT_SQL: Final = (
    "SELECT to_regclass('public.erasure_deployment_state') IS NOT NULL"
)
_CUTOVER_ACTIVATION_STATE_SQL: Final = """
SELECT cutover_at, ingress_attested_at, activated_at, first_activity_at, rollback_quarantined_at,
       isfinite(cutover_at),
       isfinite(ingress_attested_at),
       activated_at IS NULL OR isfinite(activated_at),
       first_activity_at IS NULL OR isfinite(first_activity_at),
       rollback_quarantined_at IS NULL OR isfinite(rollback_quarantined_at)
FROM public.authority_cutover_state
WHERE singleton
"""
_ERASURE_CUTOVER_ACTIVATION_STATE_SQL: Final = """
SELECT cutover_at, ingress_attested_at, activated_at, first_activity_at, rollback_quarantined_at,
       legacy_subject_key_rows, legacy_trace_subject_rows, legacy_memory_item_rows,
       legacy_run_memory_binding_rows,
       binding_backfill_digest,
       isfinite(cutover_at),
       isfinite(ingress_attested_at),
       activated_at IS NULL OR isfinite(activated_at),
       first_activity_at IS NULL OR isfinite(first_activity_at),
       rollback_quarantined_at IS NULL OR isfinite(rollback_quarantined_at),
       octet_length(binding_backfill_digest) = 32
FROM public.erasure_cutover_state
WHERE singleton
"""
_ERASURE_CUTOVER_DRAIN_SQL: Final = """
SELECT NOT EXISTS (SELECT 1 FROM public.work_queue)
   AND NOT EXISTS (SELECT 1 FROM public.trace_learning_job WHERE state = 'running')
   AND NOT EXISTS (
       SELECT 1
         FROM pg_catalog.pg_stat_activity
        WHERE pid <> pg_catalog.pg_backend_pid()
          AND usename IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')
   )
"""
_ERASURE_DEPLOYMENT_DRAIN_SQL: Final = """
SELECT NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_stat_activity
     WHERE pid <> pg_catalog.pg_backend_pid() AND usename = 'tracebed_erasure'
)
AND NOT EXISTS (
    SELECT 1 FROM public.erasure_request
     WHERE lease_token IS NOT NULL AND lease_expires_at > statement_timestamp()
)
"""

# yoyo 9 records one applied migration per row in this table.  Its hash is a
# SHA-256 of the migration id (not its source), so the source/profile fences
# remain separately authenticated.  These literals authenticate the complete
# on-disk history as an ordered set before an operator action is allowed to
# change any protected role.
_YOYO_MIGRATION_HISTORY: Final[tuple[tuple[str, str], ...]] = (
    ("0001_registries", "ca9fd297ce94f6dad44e14508a2d44f581a717e4387ec7ba32c38c1b67d6a2b4"),
    ("0002_partitioned", "22e2dc0758e77c7d1a28de420862111dc8a89da16305240bc2c7d53126e8eeb5"),
    ("0003_rls", "5181105981b30dbc0d9b20a8cedff308e51341d5bdd3501326468fcafd35320f"),
    ("0004_lifecycle", "332a0480e21dda2937e824595d1d570ccaa855848ee91a58cb47b8ecae513231"),
    ("0005_bm25", "f710f686c18ac096cf1d749008c49e24ed08a36f8eb015fb3f70a5a162b90d45"),
    ("0006_q_update_ledger", "80d963725d38aa7e6e3618d918f9894fe52f5b9927bd1d937e0488f65e8c5551"),
    ("0007_project_provisioning", "3e4a20db26abaa4ebe83aa4ae2b3d20f3f412cb413db3062db54de019ab02eb1"),
    ("0008_trace_learning_job", "0c4d2368802cc954f4d160aa3a72b162bd36e068a8f2a663d47d2bf160e59e2f"),
    ("0009_trace_index_terminal_freeze", "796f7faa2c7e658d3e2948347db53a52a44ead0a97edd382ab55548a7216a722"),
    ("0010_authority_foundation", "f33c0f4e096079c0c0c966b721ed8fb10389c9112766ec5398ab03611b4f319d"),
    ("0011_authority_cutover", "657a61cff328a14ee991d76f852d1e28af46b65fbe90f48e7338ec8caef8e271"),
    ("0012_erasure_saga", "cc6543ec143f8d79a7a3eca8001feaf0e62b3f29b417f8b636fa74004154eae6"),
    ("0013_erasure_deployment", "fba6837e672e1f41277a649d6cd5bd9f9b7c3905a0c6589e41a5d497260aab77"),
)
_YOYO_MIGRATION_COLUMNS: Final[tuple[tuple[str, str, int | None, str], ...]] = (
    ("migration_hash", "character varying", 64, "NO"),
    ("migration_id", "character varying", 255, "YES"),
    ("applied_at_utc", "timestamp without time zone", None, "YES"),
)


class _CutoverActivationState(NamedTuple):
    """Exact singleton receipt fields, including the operator-attestation time."""

    cutover_at: datetime
    ingress_attested_at: datetime
    activated_at: datetime | None
    first_activity_at: datetime | None
    rollback_quarantined_at: datetime | None


class _ErasureCutoverActivationState(NamedTuple):
    """Exact c12 singleton receipt fields, including immutable backfill proof."""

    cutover_at: datetime
    ingress_attested_at: datetime
    activated_at: datetime | None
    first_activity_at: datetime | None
    rollback_quarantined_at: datetime | None
    legacy_subject_key_rows: int
    legacy_trace_subject_rows: int
    legacy_memory_item_rows: int
    legacy_run_memory_binding_rows: int
    binding_backfill_digest: bytes
_AUTHORITY_EPOCH_PROFILE_SQL: Final = """
WITH ordered AS (
    SELECT epoch_row.*, lag(epoch) OVER (ORDER BY epoch) AS predecessor_epoch,
           lag(profile) OVER (ORDER BY epoch) AS predecessor_profile,
           lag(receipt_digest) OVER (ORDER BY epoch) AS predecessor_receipt,
           lag(result_acl_digest) OVER (ORDER BY epoch) AS predecessor_acl_digest,
           lag(result_schema_digest) OVER (ORDER BY epoch) AS predecessor_schema_digest
      FROM public.authority_acl_epoch AS epoch_row
), validated AS (
    SELECT *,
           CASE profile
               WHEN 'genuine_0010' THEN decode(
                   '8420a2ef2badd4d5c2494ddc57c87a6e6b9460100f5bcd64a24cf18989d21668', 'hex'
               )
               WHEN 'cutover_0011' THEN decode(
                   '119d169d86072837b6ccbab013fbd3b808bf9e1da2b09daab4794597f94dbb65', 'hex'
               )
               WHEN 'cutover_0012' THEN decode(
                   '19d1b45aa71030489e9c077f47b03f3c9340e9aa90ccd8cbb1aea57e30d82c16', 'hex'
               )
               WHEN 'hardened_0010' THEN decode(
                   'f809427341baeb07779d40801bd068597abba50910f6f8107fcdf8f9e722027c', 'hex'
               )
           END AS expected_contract
      FROM ordered
), latest AS (
    SELECT * FROM validated ORDER BY epoch DESC LIMIT 1
)
SELECT COALESCE((
           SELECT bool_and(
               profile_version = 2
               AND epoch = COALESCE(predecessor_epoch + 1, 0)
               AND (
                   (predecessor_profile IS NULL AND profile = 'genuine_0010')
                   OR (predecessor_profile IN ('genuine_0010', 'hardened_0010') AND profile = 'cutover_0011')
                   OR (predecessor_profile = 'cutover_0011' AND profile IN ('hardened_0010', 'cutover_0012'))
                   OR (predecessor_profile = 'cutover_0012' AND profile = 'cutover_0011')
               )
               AND profile_contract_digest = expected_contract
               AND (
                   (predecessor_epoch IS NULL
                    AND source_acl_digest = result_acl_digest
                    AND source_schema_digest = result_schema_digest)
                   OR (predecessor_epoch IS NOT NULL
                       AND source_acl_digest = predecessor_acl_digest
                       AND source_schema_digest = predecessor_schema_digest)
               )
               AND previous_receipt_digest = COALESCE(predecessor_receipt, decode(repeat('00', 32), 'hex'))
               AND receipt_digest = public.authority_acl_epoch_receipt(
                   epoch, profile, profile_version, profile_contract_digest,
                   source_acl_digest, result_acl_digest, source_schema_digest, result_schema_digest,
                   yoyo_lock_repair, previous_receipt_digest, actor_session_user, actor_current_user,
                   transitioned_at
               )
           ) FROM validated
       ), false)
       AND (SELECT result_acl_digest = public.authority_acl_security_assert(profile)
                   AND result_schema_digest = public.authority_schema_security_assert(profile)
              FROM latest)
"""
_AUTHORITY_HELPER_MANIFEST_SQL: Final = """
SELECT expected.signature,
       encode(sha256(convert_to(pg_get_functiondef(to_regprocedure(expected.signature)), 'UTF8')), 'hex')
  FROM (VALUES
      ('public.authority_acl_frame(bytea)'),
      ('public.authority_acl_set_digest(bytea[])'),
      ('public.authority_acl_epoch_receipt(bigint,public.authority_acl_profile,integer,bytea,bytea,bytea,bytea,bytea,public.authority_yoyo_lock_repair,bytea,name,name,timestamp with time zone)'),
      ('public.authority_acl_profile_actual_tuples(public.authority_acl_profile)'),
      ('public.authority_acl_security_assert(public.authority_acl_profile)'),
      ('public.authority_schema_profile_actual_tuples(public.authority_acl_profile)'),
      ('public.authority_schema_security_assert(public.authority_acl_profile)')
  ) AS expected(signature)
 ORDER BY expected.signature
"""
_AUTHORITY_HELPER_MANIFEST: Final[tuple[tuple[str, str], ...]] = (
    (
        "public.authority_acl_epoch_receipt(bigint,public.authority_acl_profile,integer,bytea,bytea,bytea,bytea,bytea,public.authority_yoyo_lock_repair,bytea,name,name,timestamp with time zone)",
        "1a26d306373a6b8a2b64df841207370f39293ca27d9f46cde4302c8b0a1ab66c",
    ),
    ("public.authority_acl_frame(bytea)", "c7269b88c25be475938b00b221ccc0ea134dca4622e3296aa9406ae3edde25ae"),
    (
        "public.authority_acl_profile_actual_tuples(public.authority_acl_profile)",
        "ff4b7c498b18f42c16e6a66159f909ed718d57d03e5c973efc25a82f27d3ef1e",
    ),
    (
        "public.authority_acl_security_assert(public.authority_acl_profile)",
        "4a35bd197fe7c36df49288cf310cb6db3140bdcbae76e640df07d15013d38640",
    ),
    ("public.authority_acl_set_digest(bytea[])", "ef071df8440c70f411688f9eb8872fc5f6863e8922ce049c2d641925d9b52f37"),
    (
        "public.authority_schema_profile_actual_tuples(public.authority_acl_profile)",
        "6ed189825b5d7a81db0d9dc6f9bfed6a44f85d7a2a579ddfced2a91ca7b8058d",
    ),
    (
        "public.authority_schema_security_assert(public.authority_acl_profile)",
        "edc64a6dbd45a2fe6c472f87e7b56d841b47ccc36cc191351c4046b4ecca9b35",
    ),
)
_SPLIT_ROLE_MEMBERSHIPS_SQL: Final = """
SELECT granted.rolname, membership.admin_option, membership.inherit_option, membership.set_option
FROM pg_auth_members AS membership
JOIN pg_roles AS granted ON granted.oid = membership.roleid
JOIN pg_roles AS member ON member.oid = membership.member
WHERE member.rolname = %s
ORDER BY granted.rolname
"""
_FOUNDATION_ROLE_MEMBERSHIP_EDGES_SQL: Final = """
SELECT granted.rolname, member.rolname,
       membership.admin_option, membership.inherit_option, membership.set_option
FROM pg_auth_members AS membership
JOIN pg_roles AS granted ON granted.oid = membership.roleid
JOIN pg_roles AS member ON member.oid = membership.member
WHERE granted.rolname = %s OR member.rolname = %s
ORDER BY granted.rolname, member.rolname
"""
_SPLIT_ROLE_STATE_SQL: Final = """
SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
       role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
       auth.rolpassword IS NOT NULL, auth.rolvaliduntil IS NULL
FROM pg_roles AS role
JOIN pg_authid AS auth ON auth.oid = role.oid
WHERE role.rolname = %s
"""
_SPLIT_ROLE_AUTH_SQL: Final = """
SELECT rolpassword LIKE 'SCRAM-SHA-256$%%',
       rolvaliduntil IS NULL OR rolvaliduntil > clock_timestamp()
FROM pg_authid
WHERE rolname = %s
"""
_PREPARED_TRANSACTIONS_CLEAN_SQL: Final = """
SELECT current_setting('max_prepared_transactions')::integer = 0
   AND NOT EXISTS (SELECT 1 FROM pg_prepared_xacts)
"""
_RUNTIME_SESSION_COUNT_SQL: Final = """
SELECT count(*)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND usename IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')
"""
_SPLIT_RUNTIME_SESSION_COUNT_SQL: Final = """
SELECT count(*)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND usename IN ('tracebed_api', 'tracebed_worker')
"""
_LEGACY_APP_RUNTIME_SESSION_COUNT_SQL: Final = """
SELECT count(*)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND usename = 'tracebed_app'
"""
_PROTECTED_ROLE_SETTINGS_SQL: Final = """
SELECT EXISTS (
    SELECT 1 FROM pg_roles
     WHERE rolname IN (
         current_user, 'tracebed_owner', 'tracebed_app', 'tracebed_api', 'tracebed_worker', 'tracebed_erasure',
         'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
     ) AND rolconfig IS NOT NULL
) OR EXISTS (
    SELECT 1 FROM pg_db_role_setting AS setting
    JOIN pg_roles AS protected_role ON protected_role.oid = setting.setrole
    WHERE protected_role.rolname IN (
        current_user, 'tracebed_owner', 'tracebed_app', 'tracebed_api', 'tracebed_worker', 'tracebed_erasure',
        'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
    )
) OR EXISTS (
    SELECT 1 FROM pg_db_role_setting
     WHERE setrole = 0
       AND setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
)
"""
_DEDICATED_CLUSTER_INVENTORY_SQL: Final = """
SELECT current_setting('tracebed.cluster_scope', true) = 'dedicated'
   AND (SELECT count(*) FROM pg_database) = 4
   AND NOT EXISTS (
       SELECT 1 FROM pg_database
        WHERE datname NOT IN (current_database(), 'postgres', 'template0', 'template1')
   )
   AND EXISTS (SELECT 1 FROM pg_database WHERE datname = 'postgres')
   AND EXISTS (SELECT 1 FROM pg_database WHERE datname = 'template1')
   AND EXISTS (
       SELECT 1 FROM pg_database WHERE datname = 'template0' AND datallowconn IS FALSE
   )
   AND session_user = current_user
   AND (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
"""
_LOCK_SQL: Final = "SELECT pg_advisory_lock(%s)"
_UNLOCK_SQL: Final = "SELECT pg_advisory_unlock(%s)"


def _role_statement(template: str, role_name: str, password: str) -> sql.Composed:
    """Safely render a fixed role identifier and an untrusted password literal.

    PostgreSQL utility statements cannot bind a role password as an extended
    query parameter.  ``psycopg.sql.Literal`` performs server-correct quoting
    without interpolating the password into a Python SQL string.
    """
    return sql.SQL(template).format(sql.Identifier(role_name), sql.Literal(password))


def _remove_role_memberships(conn: psycopg.Connection[Any], role_name: str) -> None:
    """Remove every role that could be reached with ``SET ROLE`` from the app role.

    ``NOINHERIT`` prevents automatic privilege inheritance, but does not prevent
    a member from selecting an inherited role explicitly.  An app-role membership
    in a privileged parent would therefore still provide an escalation path.  We
    revoke parent roles *from* the target role; we do not revoke this role's
    table/schema grants, which are privileges granted *to* it rather than role
    memberships.
    """
    with conn.cursor() as cursor:
        cursor.execute(_ROLE_MEMBERSHIPS_SQL, (role_name,))
        memberships = cursor.fetchall()
        for membership in memberships:
            if len(membership) != 1 or not isinstance(membership[0], str) or not membership[0]:
                raise RuntimeError("database returned an invalid tracebed application-role membership")
            cursor.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(membership[0]), sql.Identifier(role_name)
                )
            )
        cursor.execute(_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
        remaining = cursor.fetchone()

    if remaining is None or len(remaining) != 1 or remaining[0] != 0:
        if role_name == APP_ROLE:
            raise RuntimeError("tracebed application role retains a privileged role membership")
        raise RuntimeError("tracebed foundation group retains a role membership")


def _remove_app_role_memberships(conn: psycopg.Connection[Any]) -> None:
    """Compatibility wrapper for the existing application-role hardening path."""

    _remove_role_memberships(conn, APP_ROLE)


def ensure_app_role(conn: psycopg.Connection[Any], app_password: str) -> None:
    """Create or harden the login role used by Tracebed application processes.

    The role is intentionally fixed rather than configurable: every migration,
    partition grant, and application DSN names it.  Reapplying all attributes
    and removing parent-role memberships on every run repairs unsafe manual
    changes before a migration or app process can rely on the role.
    """
    if not app_password:
        raise ConfigError(f"{_APP_PASSWORD_ENV} must be set for database bootstrap")

    with conn.cursor() as cursor:
        cursor.execute(_ROLE_EXISTS_SQL, (APP_ROLE,))
        exists_row = cursor.fetchone()
        if exists_row is None:
            raise RuntimeError("database role lookup returned no result")
        if not bool(exists_row[0]):
            cursor.execute(
                _role_statement(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1",
                    APP_ROLE,
                    app_password,
                )
            )

        cursor.execute(
            _role_statement(
                "ALTER ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOINHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1",
                APP_ROLE,
                app_password,
            )
        )
    _remove_app_role_memberships(conn)
    with conn.cursor() as cursor:
        cursor.execute(_ROLE_STATE_SQL, (APP_ROLE,))
        state = cursor.fetchone()

    expected = (True, False, False, False, False, False, False, -1, False, True)
    if state is None or tuple(state) != expected:
        raise RuntimeError("tracebed application role does not have required least-privilege attributes")


def _validate_existing_app_role_for_latest_migration(conn: psycopg.Connection[Any]) -> bool:
    """Validate an existing legacy role without creating or repairing it.

    ``False`` means only that the role is absent. Every other invalid state
    aborts before latest bootstrap may create *any* protected identity.
    """

    with conn.cursor() as cursor:
        cursor.execute(_ROLE_EXISTS_SQL, (APP_ROLE,))
        exists_row = cursor.fetchone()
        if exists_row is None:
            raise RuntimeError("database role lookup returned no result")
        if not bool(exists_row[0]):
            return False
        cursor.execute(_ROLE_STATE_SQL, (APP_ROLE,))
        state = cursor.fetchone()
        cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (APP_ROLE,))
        membership_count = cursor.fetchone()
        cursor.execute(_SPLIT_ROLE_AUTH_SQL, (APP_ROLE,))
        credential = cursor.fetchone()
    if (
        state is None
        or len(state) != 10
        or state[0] not in (True, False)
        or tuple(state[1:4]) != (False, False, False)
        or state[4] is not False
        or tuple(state[5:8]) != (False, False, -1)
        or state[8] is not False
        or state[9] is not True
    ):
        raise RuntimeError("tracebed application role does not have required pre-cutover attributes")
    if credential is None or tuple(credential) != (True, True):
        raise RuntimeError("tracebed application role does not have a usable pre-cutover SCRAM credential")
    if membership_count is None or len(membership_count) != 1 or membership_count[0] != 0:
        raise RuntimeError("tracebed application role retains a role membership")
    if not _protected_role_acls_are_clean(conn, APP_ROLE, legacy_app=True):
        raise RuntimeError("tracebed application role retains unsafe access dependencies")
    return True


def _ensure_app_role_for_latest_migration(conn: psycopg.Connection[Any], app_password: str) -> None:
    """Create a missing legacy role, but never repair an existing one.

    0011's preflight is intentionally evidence preserving: an unsafe legacy
    role must abort the cutover, not be silently normalized by bootstrap just
    before the migration observes it.  The older public ``ensure_app_role``
    remains for explicitly pre-0011 maintenance paths and its focused tests.
    """

    if not app_password:
        raise ConfigError(f"{_APP_PASSWORD_ENV} must be set for database bootstrap")
    if not _validate_existing_app_role_for_latest_migration(conn):
        with conn.cursor() as cursor:
            cursor.execute("SET LOCAL password_encryption = 'scram-sha-256'")
            cursor.execute(
                _role_statement(
                    "CREATE ROLE {} NOLOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1",
                    APP_ROLE,
                    app_password,
                )
            )
        _validate_existing_app_role_for_latest_migration(conn)


def _validate_existing_foundation_roles(conn: psycopg.Connection[Any]) -> tuple[str, ...]:
    """Inspect every existing foundation group before creating any role."""

    expected = (False, False, False, False, False, False, False, -1, True, True)
    missing: list[str] = []
    for role_name in FOUNDATION_GROUP_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_ROLE_EXISTS_SQL, (role_name,))
            exists_row = cursor.fetchone()
            if exists_row is None:
                raise RuntimeError("database role lookup returned no result")
            if not bool(exists_row[0]):
                missing.append(role_name)
                continue
        with conn.cursor() as cursor:
            cursor.execute(_ROLE_STATE_SQL, (role_name,))
            state = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
            membership_count = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (role_name,))
            ownership_count = cursor.fetchone()
        if state is None or tuple(state) != expected:
            raise RuntimeError("tracebed foundation group does not have required attributes")
        if membership_count is None or len(membership_count) != 1 or membership_count[0] != 0:
            raise RuntimeError("tracebed foundation group retains a role membership")
        if ownership_count is None or len(ownership_count) != 1 or ownership_count[0] != 0:
            raise RuntimeError("tracebed foundation group owns database objects")
        if not _foundation_role_acls_are_clean(conn, role_name):
            raise RuntimeError("tracebed foundation group retains unsafe access dependencies")
    return tuple(missing)


def _validate_existing_split_roles_for_latest_migration(conn: psycopg.Connection[Any]) -> None:
    """Reject an unsafe pre-created split identity before any protected CREATE."""

    # ``_SPLIT_ROLE_STATE_SQL`` reports ``rolpassword IS NOT NULL``.  A
    # pre-cutover split role is deliberately passwordless and NOLOGIN; the
    # activation transaction is the first place a verifier may be installed.
    expected = (False, False, False, False, True, False, False, -1, False, True)
    for role_name, _ in _SPLIT_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_ROLE_EXISTS_SQL, (role_name,))
            exists_row = cursor.fetchone()
            if exists_row is None:
                raise RuntimeError("database role lookup returned no result")
            if not bool(exists_row[0]):
                continue
            cursor.execute(_SPLIT_ROLE_STATE_SQL, (role_name,))
            state = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
            membership_count = cursor.fetchone()
        if state is None or tuple(state) != expected:
            raise RuntimeError("tracebed split role does not have required pre-cutover attributes")
        if membership_count is None or len(membership_count) != 1 or membership_count[0] != 0:
            raise RuntimeError("tracebed split role retains a role membership")
        if not _protected_role_acls_are_clean(conn, role_name, legacy_app=False):
            raise RuntimeError("tracebed split role retains unsafe access dependencies")


def ensure_foundation_roles(conn: psycopg.Connection[Any]) -> None:
    """Create or verify the 0010 NOLOGIN group roles before migrations run.

    Existing group roles are never silently altered: an unsafe deployment role
    or parent membership must be repaired deliberately.  Only the legacy
    credential-bearing application role has the older repair-on-bootstrap
    behaviour; foundation groups are a future authority boundary and fail
    closed before migrations can grant them anything.
    """

    missing = _validate_existing_foundation_roles(conn)

    for role_name in missing:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1"
                ).format(sql.Identifier(role_name))
            )


def _foundation_role_acls_are_clean(conn: psycopg.Connection[Any], role_name: str) -> bool:
    """Probe ACL dependencies without persisting even allowlisted revocations.

    Bootstrap's pre-0010 CONNECT/USAGE baseline is always temporarily removed
    inside a savepoint. On subsequent runs, 0010's narrow grant matrix is
    removed too before inspecting ``pg_shdepend``. The rollback restores every
    ACL exactly, while any unlisted dependency remains visible and fails closed.
    """

    with conn.transaction(), conn.cursor() as cursor:
        cursor.execute(_FOUNDATION_POST_0010_SQL)
        post_0010 = cursor.fetchone()
        if post_0010 is None or len(post_0010) != 1 or not isinstance(post_0010[0], bool):
            raise RuntimeError("database returned an invalid authority schema probe")
        # A grant option is authority in its own right.  Do this inspection
        # before the savepoint's temporary allowlist revocations: otherwise a
        # GRANT OPTION on an expected SELECT could be hidden and restored.
        cursor.execute(_FOUNDATION_ROLE_UNSAFE_ACL_COUNT_SQL, (role_name,))
        unsafe_acl = cursor.fetchone()
        if unsafe_acl is None or len(unsafe_acl) != 1 or unsafe_acl[0] != 0:
            return False

        cursor.execute("SAVEPOINT tracebed_foundation_acl_probe")
        try:
            _revoke_foundation_baseline_acls(cursor, role_name)
            if post_0010[0]:
                _revoke_known_foundation_role_acls(cursor, role_name)
            cursor.execute(_FOUNDATION_ROLE_RESIDUAL_DEPENDENCY_COUNT_SQL, (role_name,))
            residual = cursor.fetchone()
        finally:
            cursor.execute("ROLLBACK TO SAVEPOINT tracebed_foundation_acl_probe")
            cursor.execute("RELEASE SAVEPOINT tracebed_foundation_acl_probe")
    return residual is not None and len(residual) == 1 and residual[0] == 0


def _protected_role_acls_are_clean(
    conn: psycopg.Connection[Any], role_name: str, *, legacy_app: bool
) -> bool:
    """Validate ownership/delegation and subtract only a known staged ACL set.

    This is deliberately shared by the legacy app and pre-created split roles
    before bootstrap creates anything.  The savepoint makes the allowlist
    probe evidence-preserving even on an autocommit bootstrap connection.
    """

    with conn.cursor() as cursor:
        cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (role_name,))
        ownership = cursor.fetchone()
        cursor.execute(_FOUNDATION_ROLE_UNSAFE_ACL_COUNT_SQL, (role_name,))
        unsafe_acl = cursor.fetchone()
    if (
        ownership is None
        or len(ownership) != 1
        or ownership[0] != 0
        or unsafe_acl is None
        or len(unsafe_acl) != 1
        or unsafe_acl[0] != 0
    ):
        return False
    with conn.transaction(), conn.cursor() as cursor:
        cursor.execute("SAVEPOINT tracebed_protected_acl_probe")
        try:
            if legacy_app:
                _revoke_known_legacy_app_role_acls(cursor)
            cursor.execute(_FOUNDATION_ROLE_RESIDUAL_DEPENDENCY_COUNT_SQL, (role_name,))
            residual = cursor.fetchone()
        finally:
            cursor.execute("ROLLBACK TO SAVEPOINT tracebed_protected_acl_probe")
            cursor.execute("RELEASE SAVEPOINT tracebed_protected_acl_probe")
    return residual is not None and len(residual) == 1 and residual[0] == 0


def _revoke_known_legacy_app_role_acls(cursor: psycopg.Cursor[Any]) -> None:
    """Temporarily subtract the exact pre-cutover legacy app ACL surface."""

    cursor.execute(
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
            sql.Identifier(cursor.connection.info.dbname), sql.Identifier(APP_ROLE)
        )
    )
    cursor.execute("REVOKE USAGE ON SCHEMA public FROM tracebed_app")
    for relation_name in (
        "project",
        "principal",
        "agent_type",
        "agent_registration",
        "embedding_model",
        "scoring_epoch",
        "project_config",
        "agent_type_config",
        "killswitch_state",
        "work_queue",
        "dead_letter",
        "memory_item",
        "memory_link",
        "derived_state",
        "trace_subject",
        "subject_key",
        "outcome_event",
        "injection_log",
        "retrieval_event",
        "blackboard_entry",
        "invalidation_event",
        "spend_ledger",
        "review_queue",
        "memory_status_log",
        "memory_q_update",
    ):
        cursor.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{relation_name}",))
        relation_exists = cursor.fetchone()
        if relation_exists != (True,):
            continue
        cursor.execute(
                sql.SQL("REVOKE SELECT, INSERT, UPDATE, DELETE ON public.{} FROM {}").format(
                    sql.Identifier(relation_name), sql.Identifier(APP_ROLE)
                )
            )
    _revoke_exact_yoyo_lock_acl(cursor)
    for relation_name, privileges in (
        ("principal_grant", "SELECT"),
        ("run_owner", "SELECT, INSERT"),
        ("trace_index", "SELECT, INSERT, UPDATE"),
        ("trace_learning_job", "SELECT, INSERT, UPDATE"),
    ):
        cursor.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{relation_name}",))
        if cursor.fetchone() == (True,):
            cursor.execute(
                sql.SQL("REVOKE {} ON public.{} FROM {}").format(
                    sql.SQL(privileges), sql.Identifier(relation_name), sql.Identifier(APP_ROLE)
                )
            )
    cursor.execute(
        "SELECT child.relname, parent.relname FROM pg_inherits AS inheritance "
        "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
        "JOIN pg_class AS parent ON parent.oid = inheritance.inhparent "
        "JOIN pg_namespace AS child_schema ON child_schema.oid = child.relnamespace "
        "JOIN pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace "
        "WHERE child_schema.nspname = 'public' AND parent_schema.nspname = 'public' "
        "AND parent.relname IN ('memory_item','memory_link','derived_state','trace_index',"
        "'trace_subject','subject_key','outcome_event','injection_log','retrieval_event',"
        "'blackboard_entry','invalidation_event','spend_ledger','review_queue',"
        "'memory_status_log','memory_q_update','trace_learning_job','run_owner')"
    )
    for row in cursor.fetchall():
        if len(row) != 2 or not isinstance(row[0], str) or not isinstance(row[1], str):
            raise RuntimeError("database returned an invalid partition relation")
        privileges = "SELECT, INSERT, UPDATE, DELETE"
        if row[1] == "run_owner":
            privileges = "SELECT, INSERT"
        elif row[1] in {"trace_index", "trace_learning_job"}:
            privileges = "SELECT, INSERT, UPDATE"
        cursor.execute(
            sql.SQL("REVOKE {} ON public.{} FROM {}").format(
                sql.SQL(privileges), sql.Identifier(row[0]), sql.Identifier(APP_ROLE)
            )
        )
    for sequence_name in ("work_queue_id_seq", "scoring_epoch_epoch_id_seq"):
        cursor.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{sequence_name}",))
        sequence_exists = cursor.fetchone()
        if sequence_exists == (True,):
            cursor.execute(
                sql.SQL("REVOKE USAGE, SELECT ON SEQUENCE public.{} FROM {}").format(
                    sql.Identifier(sequence_name), sql.Identifier(APP_ROLE)
                )
            )
    cursor.execute(
        "SELECT to_regnamespace('tokenizer_catalog') IS NOT NULL, "
        "to_regnamespace('bm25_catalog') IS NOT NULL"
    )
    schemas = cursor.fetchone()
    if schemas is None or len(schemas) != 2 or not all(isinstance(value, bool) for value in schemas):
        raise RuntimeError("database returned an invalid extension schema probe")
    if schemas[0]:
        cursor.execute("REVOKE USAGE ON SCHEMA tokenizer_catalog FROM tracebed_app")
        cursor.execute(
            "REVOKE SELECT ON tokenizer_catalog.tokenizer, tokenizer_catalog.text_analyzer, "
            "tokenizer_catalog.model, tokenizer_catalog.stopwords, tokenizer_catalog.synonym "
            "FROM tracebed_app"
        )
    if schemas[1]:
        cursor.execute("REVOKE USAGE ON SCHEMA bm25_catalog FROM tracebed_app")
    # 0011 rollback restores this small legacy extension surface directly to
    # the disabled app role because PUBLIC stays hardened.  The pre-cutover
    # probe must subtract it when checking a rollback -> reapply, but must
    # also tolerate a genuinely empty cluster before the extension migrations
    # have run.
    for routine_name in (
        "tokenizer_catalog.tokenize(text,text)",
        "bm25_catalog.to_bm25query(regclass,bm25_catalog.bm25vector)",
        "bm25_catalog.search_bm25query(bm25_catalog.bm25vector,bm25_catalog.bm25query)",
        "bm25_catalog._vchord_bm25_cast_array_to_bm25vector(integer[],integer,boolean)",
        "public.halfvec(halfvec,integer,boolean)",
        "public.cosine_distance(halfvec,halfvec)",
    ):
        cursor.execute("SELECT to_regprocedure(%s)::text", (routine_name,))
        routine = cursor.fetchone()
        if routine is None or len(routine) != 1:
            raise RuntimeError("database returned an invalid extension routine probe")
        if routine[0] is not None:
            if not isinstance(routine[0], str):
                raise RuntimeError("database returned an invalid extension routine probe")
            cursor.execute(
                sql.SQL("REVOKE EXECUTE ON FUNCTION {} FROM {}").format(
                    sql.SQL(routine[0]), sql.Identifier(APP_ROLE)
                )
            )
    for type_name in ("public.halfvec", "bm25_catalog.bm25vector", "bm25_catalog.bm25query"):
        cursor.execute("SELECT to_regtype(%s)::text", (type_name,))
        type_row = cursor.fetchone()
        if type_row is None or len(type_row) != 1:
            raise RuntimeError("database returned an invalid extension type probe")
        if type_row[0] is not None:
            if not isinstance(type_row[0], str):
                raise RuntimeError("database returned an invalid extension type probe")
            cursor.execute(
                sql.SQL("REVOKE USAGE ON TYPE {} FROM {}").format(
                    sql.SQL(type_row[0]), sql.Identifier(APP_ROLE)
                )
            )
    cursor.execute("SELECT to_regprocedure('public.subject_digests_are_valid(bytea[])') IS NOT NULL")
    if cursor.fetchone() == (True,):
        cursor.execute("REVOKE EXECUTE ON FUNCTION public.subject_digests_are_valid(bytea[]) FROM tracebed_app")
    cursor.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM tracebed_app"
    )
    cursor.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE USAGE, SELECT ON SEQUENCES FROM tracebed_app"
    )


def _revoke_exact_yoyo_lock_acl(cursor: psycopg.Cursor[Any]) -> None:
    """Remove only yoyo 9's verified legacy lock-table DML artifact.

    A table merely named ``yoyo_lock`` is not sufficient evidence. Its
    namespace, owner, columns, default, and primary key must match yoyo 9.
    The app ACL is either the genuine-0010 direct DML surface (which this
    savepoint probe subtracts) or the hardened/cutover empty surface (which
    remains empty). Partial or delegated grants are never normalized. The
    underscored spelling is never a recognized artifact.
    """

    cursor.execute("SELECT to_regclass('public._yoyo_lock') IS NOT NULL")
    if cursor.fetchone() == (True,):
        raise RuntimeError("unexpected underscored yoyo lock relation")
    cursor.execute("SELECT to_regclass('public.yoyo_lock') IS NOT NULL")
    if cursor.fetchone() != (True,):
        return
    cursor.execute(
        """
        SELECT relation.relkind = 'r'
           AND relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
           AND (
               SELECT array_agg(
                   attribute.attname || '|' || format_type(attribute.atttypid, attribute.atttypmod)
                   || '|' || attribute.attnotnull::text || '|'
                   || COALESCE(pg_get_expr(default_value.adbin, default_value.adrelid), '')
                   ORDER BY attribute.attnum
               )
                 FROM pg_attribute AS attribute
                 LEFT JOIN pg_attrdef AS default_value
                   ON default_value.adrelid = attribute.attrelid
                  AND default_value.adnum = attribute.attnum
                WHERE attribute.attrelid = relation.oid
                  AND attribute.attnum > 0 AND NOT attribute.attisdropped
           ) = ARRAY[
               'locked|integer|true|1',
               'ctime|timestamp without time zone|false|',
               'pid|integer|true|'
           ]
           AND (
               SELECT count(*) = 1 AND bool_and(constraint_row.conkey = ARRAY[1]::smallint[])
                 FROM pg_constraint AS constraint_row
                WHERE constraint_row.conrelid = relation.oid AND constraint_row.contype = 'p'
           )
           AND COALESCE((
               SELECT array_agg(privilege.privilege_type ORDER BY privilege.privilege_type)
                 FROM aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS privilege
                 JOIN pg_roles AS grantee ON grantee.oid = privilege.grantee
                WHERE grantee.rolname = 'tracebed_app'
           ), ARRAY[]::text[]) IN (
               ARRAY[]::text[], ARRAY['DELETE', 'INSERT', 'SELECT', 'UPDATE']
           )
          FROM pg_class AS relation
         WHERE relation.oid = 'public.yoyo_lock'::regclass
        """
    )
    if cursor.fetchone() != (True,):
        raise RuntimeError("yoyo lock relation does not have the expected control-table shape")
    cursor.execute("REVOKE SELECT, INSERT, UPDATE, DELETE ON public.yoyo_lock FROM tracebed_app")


def _revoke_known_foundation_role_acls(cursor: psycopg.Cursor[Any], role_name: str) -> None:
    """Temporarily remove exactly the 0010 group grant matrix, never broad ACLs."""

    role = sql.Identifier(role_name)
    if role_name == "tracebed_api_group":
        cursor.execute(
            sql.SQL("REVOKE SELECT ON project, principal, agent_type, agent_registration, principal_grant FROM {}").format(role)
        )
        cursor.execute(sql.SQL("REVOKE SELECT, INSERT ON run_owner, work_queue FROM {}").format(role))
        cursor.execute(sql.SQL("REVOKE USAGE, SELECT ON SEQUENCE work_queue_id_seq FROM {}").format(role))
        cursor.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION subject_digests_are_valid(bytea[]) FROM {}").format(role))
        _revoke_run_owner_child_acls(cursor, role, "SELECT, INSERT")
    elif role_name == "tracebed_worker_group":
        cursor.execute(
            sql.SQL("REVOKE SELECT ON project, principal, agent_type, agent_registration, principal_grant, run_owner FROM {}").format(role)
        )
        cursor.execute(sql.SQL("REVOKE SELECT, UPDATE, DELETE ON work_queue FROM {}").format(role))
        cursor.execute(sql.SQL("REVOKE SELECT, INSERT ON dead_letter FROM {}").format(role))
        cursor.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION subject_digests_are_valid(bytea[]) FROM {}").format(role))
        _revoke_run_owner_child_acls(cursor, role, "SELECT")


def _revoke_foundation_baseline_acls(cursor: psycopg.Cursor[Any], role_name: str) -> None:
    """Temporarily subtract bootstrap's pre-0010 CONNECT/USAGE baseline."""

    role = sql.Identifier(role_name)
    cursor.execute(
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
            sql.Identifier(cursor.connection.info.dbname), role
        )
    )
    cursor.execute(sql.SQL("REVOKE USAGE ON SCHEMA public FROM {}").format(role))


def _revoke_run_owner_child_acls(
    cursor: psycopg.Cursor[Any], role: sql.Identifier, privileges: str
) -> None:
    cursor.execute(
        "SELECT child.relname FROM pg_inherits AS inheritance "
        "JOIN pg_class AS child ON child.oid = inheritance.inhrelid "
        "WHERE inheritance.inhparent = 'run_owner'::regclass"
    )
    for row in cursor.fetchall():
        if len(row) != 1 or not isinstance(row[0], str):
            raise RuntimeError("database returned an invalid run-owner child relation")
        cursor.execute(sql.SQL("REVOKE {} ON {} FROM {}").format(sql.SQL(privileges), sql.Identifier(row[0]), role))


def _grant_database_access(conn: psycopg.Connection[Any]) -> None:
    """Grant only the connection/schema baseline the migrations expect."""
    database_name = conn.info.dbname
    if not database_name:
        raise RuntimeError("owner connection has no database name")
    with conn.cursor() as cursor:
        for role_name in (APP_ROLE, *FOUNDATION_GROUP_ROLES):
            cursor.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(database_name), sql.Identifier(role_name)
                )
            )
            cursor.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role_name))
            )
        cursor.execute(
            sql.SQL("ALTER DATABASE {} SET tracebed.project_id TO ''").format(
                sql.Identifier(database_name)
            )
        )


def _cutover_present(conn: psycopg.Connection[Any]) -> bool:
    with conn.cursor() as cursor:
        cursor.execute(_CUTOVER_PRESENT_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], bool):
        raise RuntimeError("database returned an invalid authority-cutover schema probe")
    return row[0]


def _erasure_cutover_present(conn: psycopg.Connection[Any]) -> bool:
    """Probe only for the c12 singleton relation before reading its receipt."""

    with conn.cursor() as cursor:
        cursor.execute(_ERASURE_CUTOVER_PRESENT_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], bool):
        raise RuntimeError("database returned an invalid erasure-cutover schema probe")
    return row[0]


def _erasure_deployment_present(conn: psycopg.Connection[Any]) -> bool:
    """Whether the E4 authenticated deployment singleton exists."""

    with conn.cursor() as cursor:
        cursor.execute(_ERASURE_DEPLOYMENT_PRESENT_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], bool):
        raise RuntimeError("database returned an invalid erasure deployment schema probe")
    return row[0]


def _ensure_authority_epoch_profile_current(conn: psycopg.Connection[Any]) -> None:
    """Refuse credential publication when the authenticated schema/profile drifted.

    The append-only epoch is useful only if every activation and active retry
    recomputes both semantic catalog digests.  This is read-only: bootstrap
    never repairs an ACL, RLS, trigger, or partition topology mismatch.
    """

    try:
        with conn.cursor() as cursor:
            cursor.execute(_AUTHORITY_HELPER_MANIFEST_SQL)
            helper_manifest = cursor.fetchall()
            if helper_manifest != list(_AUTHORITY_HELPER_MANIFEST):
                raise RuntimeError("tracebed authority digest helper manifest is not authenticated")
            cursor.execute(_AUTHORITY_EPOCH_PROFILE_SQL)
            row = cursor.fetchone()
    except psycopg.Error as exc:
        raise RuntimeError("tracebed authority epoch profile is not current") from exc
    if row != (True,):
        raise RuntimeError("tracebed authority epoch profile is not current")


def _latest_authority_epoch_profile(conn: psycopg.Connection[Any]) -> str:
    """Return the authenticated latest profile without accepting a missing/forged row."""

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT profile::text FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1")
            row = cursor.fetchone()
    except psycopg.Error as exc:
        raise RuntimeError("tracebed authority epoch profile is not current") from exc
    if row is None or len(row) != 1 or row[0] not in {
        "genuine_0010",
        "hardened_0010",
        "cutover_0011",
        "cutover_0012",
    }:
        raise RuntimeError("tracebed authority epoch profile is not current")
    return str(row[0])


def _ensure_latest_authority_epoch_profile(
    conn: psycopg.Connection[Any], *, expected: Literal["cutover_0011", "cutover_0012"]
) -> None:
    """Require the exact epoch that authorizes a c11/c12 lifecycle transition."""

    _ensure_authority_epoch_profile_current(conn)
    if _latest_authority_epoch_profile(conn) != expected:
        raise RuntimeError("tracebed authority epoch is not at the required lifecycle boundary")


def _cutover_state_validation_barrier() -> None:
    """Narrow test seam after the authenticated profile and before receipt use."""


def _validate_split_passwords(api_password: str, worker_password: str) -> None:
    """Reject unusable split credentials before an authority cutover can stage roles."""

    _require_cleartext_credential(api_password, _API_PASSWORD_ENV)
    _require_cleartext_credential(worker_password, _WORKER_PASSWORD_ENV)
    if api_password == worker_password:
        raise ConfigError("split database passwords must be distinct")


def _ensure_protected_role_settings_clean(conn: psycopg.Connection[Any]) -> None:
    """Reject role/database GUCs that could change authority SQL semantics."""

    with conn.cursor() as cursor:
        cursor.execute(_PROTECTED_ROLE_SETTINGS_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or row[0] is not False:
        raise RuntimeError("tracebed protected role or database settings are not clean")


def _ensure_prepared_transactions_clean(conn: psycopg.Connection[Any]) -> None:
    """Require stop-the-world prepared-transaction safety before cutover/login."""

    with conn.cursor() as cursor:
        cursor.execute(_PREPARED_TRANSACTIONS_CLEAN_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or row[0] is not True:
        raise RuntimeError("tracebed authority bootstrap requires no prepared transactions")


def _ensure_no_runtime_sessions(conn: psycopg.Connection[Any]) -> None:
    """Do not activate/quarantine while a split or legacy session survives."""

    with conn.cursor() as cursor:
        cursor.execute(_RUNTIME_SESSION_COUNT_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], int) or row[0] != 0:
        raise RuntimeError("tracebed authority bootstrap requires no runtime sessions")


def _ensure_no_legacy_app_sessions(conn: psycopg.Connection[Any]) -> None:
    """Require app-session evidence to be empty without touching split residue."""

    with conn.cursor() as cursor:
        cursor.execute(_LEGACY_APP_RUNTIME_SESSION_COUNT_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], int) or row[0] != 0:
        raise RuntimeError("tracebed authority bootstrap requires no legacy app sessions")


def _terminate_runtime_role_sessions(
    conn: psycopg.Connection[Any], roles: tuple[str, ...]
) -> None:
    """Terminate only a fixed runtime identity set and wait for completion."""

    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity "
            "WHERE pid <> pg_backend_pid() AND usename = ANY(%s)",
            (list(roles),),
        )
        results = cursor.fetchall()
        if any(len(row) != 1 or row[0] is not True for row in results):
            raise RuntimeError("tracebed authority bootstrap could not terminate runtime sessions")
        # PostgreSQL may otherwise keep an old pg_stat_activity snapshot for
        # this transaction.  Re-clear/recheck once; a surviving backend is a
        # refusal, never a reason to sleep blindly during a security fence.
        for _ in range(2):
            cursor.execute("SELECT pg_stat_clear_snapshot()")
            cursor.fetchone()
            cursor.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE pid <> pg_backend_pid() AND usename = ANY(%s)",
                (list(roles),),
            )
            row = cursor.fetchone()
            if (
                row is None
                or len(row) != 1
                or not isinstance(row[0], int)
                or isinstance(row[0], bool)
                or row[0] < 0
            ):
                raise RuntimeError("database returned an invalid runtime session count")
            if row[0] == 0:
                return
    raise RuntimeError("tracebed authority bootstrap could not quarantine runtime sessions")


def _terminate_split_role_sessions(conn: psycopg.Connection[Any]) -> None:
    """Quarantine crash-residue sessions after both split roles are NOLOGIN.

    ``ALTER ROLE ... NOLOGIN`` does not revoke a session that authenticated
    before the transaction committed.  Marker-null active credentials are
    therefore never merely disabled and retried: terminate every surviving
    split-role backend, then require the global runtime set to be empty before
    a later activation can publish fresh credentials.
    """

    _terminate_runtime_role_sessions(conn, (API_ROLE, WORKER_ROLE))


def _split_role_sessions_present(conn: psycopg.Connection[Any]) -> bool:
    """Return whether a marker-null split identity still owns a backend."""

    with conn.cursor() as cursor:
        cursor.execute(_SPLIT_RUNTIME_SESSION_COUNT_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], int) or row[0] < 0:
        raise RuntimeError("database returned an invalid split role session count")
    return row[0] > 0


def _ensure_dedicated_cluster_inventory(conn: psycopg.Connection[Any]) -> None:
    """Repeat the migration's dedicated-cluster proof before enabling logins."""

    with conn.cursor() as cursor:
        cursor.execute(_DEDICATED_CLUSTER_INVENTORY_SQL)
        row = cursor.fetchone()
    if row is None or len(row) != 1 or row[0] is not True:
        raise RuntimeError("tracebed authority bootstrap requires the dedicated cluster inventory")


def _require_cleartext_credential(value: object, env_name: str) -> str:
    """Validate one supplied secret without normalising its raw bytes/text.

    PostgreSQL's SCRAM verifier syntax is not a reusable password.  Treating
    it as a cleartext input both surprises operators and can publish a
    verifier for a secret nobody possesses, so reject it before opening an
    owner connection.
    """

    if not isinstance(value, str) or not value:
        raise ConfigError(f"{env_name} must be set for database bootstrap")
    if value.startswith("SCRAM-SHA-256$"):
        raise ConfigError(f"{env_name} must be a cleartext credential")
    return value


def _authority_owner_url_fields(
    owner_dsn: object,
) -> tuple[str, SplitResult, dict[str, str | int | None]]:
    """Parse the only DSN form the authority/bootstrap migration path accepts.

    The repository-owned yoyo runner is deliberately URL-only: yoyo selects
    its psycopg backend from the URI scheme, while keyword libpq conninfo has
    no lossless, trusted conversion into that backend URI.  Reject keyword
    conninfo before an owner connection can quarantine roles or take a lock,
    instead of accepting it through bootstrap and failing later in the runner.
    This contract applies only to authority bootstrap/migration work; ordinary
    runtime psycopg consumers retain their own DSN contracts.
    """

    try:
        owner_dsn, parsed = parse_authority_migration_url(owner_dsn)
    except ValueError as exc:
        raise ConfigError("owner DSN must be a PostgreSQL URL for authority bootstrap") from exc
    try:
        owner_fields = conninfo_to_dict(owner_dsn)
    except psycopg.ProgrammingError as exc:
        raise ConfigError("owner DSN must be a PostgreSQL URL for authority bootstrap") from exc
    # ``conninfo_to_dict`` is still the parser of record for libpq escaping and
    # URI query fields. Require each authority connection coordinate explicitly
    # so a URL whose form is valid but whose destination is implicit cannot
    # defer a failure until after role work begins.
    for required in ("dbname", "user", "host"):
        if not isinstance(owner_fields.get(required), str) or not owner_fields[required]:
            raise ConfigError(
                "owner DSN must include non-empty database, user, and host for authority bootstrap"
            )
    return owner_dsn, parsed, owner_fields


def _validate_authority_inputs(
    owner_dsn: object,
    app_password: object,
    api_password: object,
    worker_password: object,
    cluster_scope: object,
    *,
    ingress_quarantined: object,
) -> tuple[str, str, str, str]:
    """Fail closed before an owner connection can mutate cluster-global roles.

    ``TB_0011_INGRESS_QUARANTINED=true`` is an operator attestation that an
    external firewall/HBA/service fence is already closed.  It is deliberately
    not represented as a claim that SQL can inspect HBA or network state.
    The trusted DSN below carries this attestation to 0011 as a session GUC so
    direct yoyo invocation cannot silently bypass the receipt.
    """

    if cluster_scope != _DEDICATED_CLUSTER_SCOPE:
        raise ConfigError(f"{_CLUSTER_SCOPE_ENV} must be exactly {_DEDICATED_CLUSTER_SCOPE!r}")
    if ingress_quarantined is not True:
        raise ConfigError(
            f"{HBA_PROFILE_ENV} must select the Compose-v1 HBA profile; "
            f"{LEGACY_INGRESS_ENV} is not supported"
        )
    owner_dsn, _parsed, owner_fields = _authority_owner_url_fields(owner_dsn)
    if "options" in owner_fields:
        raise ConfigError("owner DSN must not set PostgreSQL options during authority bootstrap")
    owner_password = owner_fields.get("password")
    if isinstance(owner_password, str) and owner_password.startswith("SCRAM-SHA-256$"):
        raise ConfigError("owner DSN password must be a cleartext credential")
    app = _require_cleartext_credential(app_password, _APP_PASSWORD_ENV)
    api = _require_cleartext_credential(api_password, _API_PASSWORD_ENV)
    worker = _require_cleartext_credential(worker_password, _WORKER_PASSWORD_ENV)
    if api == worker:
        raise ConfigError("split database passwords must be distinct")
    return owner_dsn, app, api, worker


def _validate_bootstrap_action(
    value: object,
) -> Literal[
    "apply",
    "rollback",
    "rollback-0011",
    "cutover-0012",
    "cutover-0012-closed",
    "cutover-0013",
    "rollback-0012",
    "rollback-0013",
    "admission-close",
    "admission-open",
    "runtime-drain-assert",
    "admission-assert-closed",
    "erasure-drain-assert",
    "start-preflight",
    "rollback-recovery-preflight",
    "rollback-refusal-recovery-preflight",
]:
    """Accept only closed owner-side lifecycle operations."""

    if value not in (
        _BOOTSTRAP_APPLY_ACTION,
        _BOOTSTRAP_ROLLBACK_ACTION,
        _BOOTSTRAP_ROLLBACK_0011_ACTION,
        _BOOTSTRAP_CUTOVER_0012_ACTION,
        _BOOTSTRAP_CUTOVER_0012_CLOSED_ACTION,
        _BOOTSTRAP_CUTOVER_0013_ACTION,
        _BOOTSTRAP_ROLLBACK_0012_ACTION,
        _BOOTSTRAP_ROLLBACK_0013_ACTION,
        _BOOTSTRAP_ADMISSION_CLOSE_ACTION,
        _BOOTSTRAP_ADMISSION_OPEN_ACTION,
        _BOOTSTRAP_RUNTIME_DRAIN_ASSERT_ACTION,
        _BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION,
        _BOOTSTRAP_ERASURE_DRAIN_ASSERT_ACTION,
        _BOOTSTRAP_START_PREFLIGHT_ACTION,
        _BOOTSTRAP_ROLLBACK_RECOVERY_PREFLIGHT_ACTION,
        _BOOTSTRAP_ROLLBACK_REFUSAL_RECOVERY_PREFLIGHT_ACTION,
    ):
        raise ConfigError(
            f"{_BOOTSTRAP_ACTION_ENV} must be exactly "
            f"one of the supported owner lifecycle actions"
        )
    return value


def _dedicated_cluster_dsn(
    owner_dsn: str, cluster_scope: str, *, ingress_quarantined: bool = False
) -> str:
    """Build the only owner DSN accepted for 0011 authority work.

    Existing caller ``options`` are rejected rather than merged: a caller
    supplied search path or custom GUC must not be able to shadow the trusted
    cluster/ingress assertions.  The ingress value is an operator assertion,
    not an attempted proof of external HBA or firewall state.
    """

    if cluster_scope != _DEDICATED_CLUSTER_SCOPE:
        raise ConfigError(f"{_CLUSTER_SCOPE_ENV} must be exactly {_DEDICATED_CLUSTER_SCOPE!r}")
    _owner_dsn, parsed, owner_fields = _authority_owner_url_fields(owner_dsn)
    if "options" in owner_fields:
        raise ConfigError("owner DSN must not set PostgreSQL options during authority bootstrap")
    options = "-c tracebed.cluster_scope=dedicated"
    if ingress_quarantined:
        options += f" -c {_INGRESS_QUARANTINED_GUC}=on"
    options += " -c search_path=public,pg_catalog"
    query = parse_qsl(parsed.query, keep_blank_values=True)
    # ``conninfo_to_dict`` catches libpq's view of URI fields; retain this
    # direct duplicate-key check as defence in depth before composing the one
    # trusted options value.
    if any(key == "options" for key, _ in query):
        raise ConfigError("owner DSN must not set PostgreSQL options during authority bootstrap")
    query.append(("options", options))
    return trusted_authority_dsn(
        urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query, quote_via=quote), parsed.fragment)
        ),
        options,
    )


def ensure_split_roles_pre_activation(conn: psycopg.Connection[Any]) -> None:
    """Verify the staged split roles before granting either one LOGIN.

    The migration owns role creation, role memberships, and object ACLs.  Bootstrap
    deliberately does not repair any of them: a failed activation must leave both
    credentials unusable until an operator resolves the drift and retries.
    """

    expected_state = (False, False, False, False, True, False, False, -1, True, True)
    for role_name, group_name in _SPLIT_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_ROLE_STATE_SQL, (role_name,))
            state = cursor.fetchone()
            cursor.execute(_SPLIT_ROLE_MEMBERSHIPS_SQL, (role_name,))
            memberships = cursor.fetchall()
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
            membership_count = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (role_name,))
            ownership_count = cursor.fetchone()
        if state is None or tuple(state) != expected_state:
            raise RuntimeError("tracebed split role does not have required pre-activation attributes")
        expected_memberships = [(group_name, False, True, False)]
        if memberships != expected_memberships:
            raise RuntimeError("tracebed split role does not have the required membership")
        if membership_count != (1,) or ownership_count != (0,):
            raise RuntimeError("tracebed split role has unsafe authority dependencies")


def _classify_split_role_publication(
    conn: psycopg.Connection[Any],
) -> Literal["staged", "active", "residue"]:
    """Classify only safe marker-null publication residue.

    Membership, ownership, validity, and role-attribute drift are never
    normalized.  The narrowly permitted residue class consists solely of
    safe split identities with an interrupted combination of LOGIN and
    verifier-null state; bootstrap can atomically quarantine that class before
    terminating its surviving sessions.
    """

    login_states: list[bool] = []
    password_null_states: list[bool] = []
    for role_name, group_name in _SPLIT_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_ROLE_STATE_SQL, (role_name,))
            row = cursor.fetchone()
            cursor.execute(_SPLIT_ROLE_MEMBERSHIPS_SQL, (role_name,))
            memberships = cursor.fetchall()
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
            membership_count = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (role_name,))
            ownership_count = cursor.fetchone()
            cursor.execute(_SPLIT_ROLE_AUTH_SQL, (role_name,))
            auth = cursor.fetchone()
        if (
            row is None
            or tuple(row[1:8]) != (False, False, False, True, False, False, -1)
            or row[9] is not True
        ):
            raise RuntimeError("database returned an invalid tracebed split-role state")
        if memberships != [(group_name, False, True, False)]:
            raise RuntimeError("tracebed split role does not have the required membership")
        if membership_count != (1,) or ownership_count != (0,):
            raise RuntimeError("tracebed split role has unsafe authority dependencies")
        if row[8] is False and auth != (True, True):
            raise RuntimeError("tracebed split role has an unsafe credential residue")
        if row[8] is True and auth != (None, True):
            raise RuntimeError("tracebed split role has an unsafe credential residue")
        login_states.append(row[0])
        password_null_states.append(row[8])
    if all(not value for value in login_states) and all(password_null_states):
        return "staged"
    if all(login_states) and all(not value for value in password_null_states):
        return "active"
    return "residue"


def _ensure_split_roles_active(conn: psycopg.Connection[Any]) -> None:
    """Verify a completed activation without modifying role state or credentials."""

    expected_state = (True, False, False, False, True, False, False, -1)
    for role_name, group_name in _SPLIT_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_SPLIT_ROLE_STATE_SQL, (role_name,))
            state = cursor.fetchone()
            cursor.execute(_SPLIT_ROLE_MEMBERSHIPS_SQL, (role_name,))
            memberships = cursor.fetchall()
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
            membership_count = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (role_name,))
            ownership_count = cursor.fetchone()
            cursor.execute(_SPLIT_ROLE_AUTH_SQL, (role_name,))
            auth = cursor.fetchone()
        if state is None or tuple(state) != (*expected_state, True, True):
            raise RuntimeError("tracebed split role does not have required active attributes")
        if memberships != [(group_name, False, True, False)]:
            raise RuntimeError("tracebed split role does not have the required membership")
        if membership_count != (1,) or ownership_count != (0,):
            raise RuntimeError("tracebed split role has unsafe authority dependencies")
        if auth is None or tuple(auth) != (True, True):
            raise RuntimeError("tracebed split role does not have a usable SCRAM credential")


def _decode_cutover_activation_state(row: object) -> _CutoverActivationState:
    """Validate real receipt timestamps; booleans cannot prove provenance."""

    if not isinstance(row, tuple) or len(row) != 10:
        raise RuntimeError("tracebed authority cutover state is invalid")
    (
        cutover_at,
        ingress_attested_at,
        activated_at,
        first_activity_at,
        rollback_at,
        cutover_finite,
        ingress_finite,
        activated_finite,
        first_activity_finite,
        rollback_finite,
    ) = row
    if (cutover_finite, ingress_finite, activated_finite, first_activity_finite, rollback_finite) != (
        True,
        True,
        True,
        True,
        True,
    ):
        raise RuntimeError("tracebed authority cutover state is invalid")
    if not isinstance(cutover_at, datetime) or not isinstance(ingress_attested_at, datetime):
        raise RuntimeError("tracebed authority cutover state is invalid")
    if any(value is not None and not isinstance(value, datetime) for value in (activated_at, first_activity_at, rollback_at)):
        raise RuntimeError("tracebed authority cutover state is invalid")
    state = _CutoverActivationState(
        cutover_at, ingress_attested_at, activated_at, first_activity_at, rollback_at
    )
    # Equality is intentionally exact.  The INSERT below uses two calls to
    # statement_timestamp(), whose PostgreSQL semantics make them equal within
    # the one statement; accepting merely a non-null attestation lets a later
    # rewrite fabricate a plausible receipt.
    if state.ingress_attested_at != state.cutover_at:
        raise RuntimeError("tracebed authority cutover ingress receipt is invalid")
    if state.activated_at is not None and state.activated_at < state.cutover_at:
        raise RuntimeError("tracebed authority cutover state is invalid")
    if state.first_activity_at is not None and (
        state.activated_at is None or state.first_activity_at < state.activated_at
    ):
        raise RuntimeError("tracebed authority cutover state is invalid")
    if state.rollback_quarantined_at is not None and (
        state.activated_at is None
        or state.rollback_quarantined_at < state.activated_at
        or state.first_activity_at is not None
    ):
        raise RuntimeError("tracebed authority cutover state is invalid")
    return state


def _cutover_activation_state(conn: psycopg.Connection[Any]) -> _CutoverActivationState:
    """Read the singleton receipt without accepting impossible activity states."""

    try:
        with conn.cursor() as cursor:
            cursor.execute(_CUTOVER_ACTIVATION_STATE_SQL)
            row = cursor.fetchone()
    except psycopg.Error as exc:
        # In particular, psycopg rejects PostgreSQL ``infinity`` timestamps
        # when decoding to Python.  That is an invalid receipt, not an
        # infrastructure condition a caller may work around.
        raise RuntimeError("tracebed authority cutover state is invalid") from exc
    return _decode_cutover_activation_state(row)


def _decode_erasure_cutover_activation_state(row: object) -> _ErasureCutoverActivationState:
    """Validate the c12 singleton without trusting merely plausible timestamps."""

    if not isinstance(row, tuple) or len(row) != 16:
        raise RuntimeError("tracebed erasure cutover state is invalid")
    (
        cutover_at,
        ingress_attested_at,
        activated_at,
        first_activity_at,
        rollback_at,
        legacy_subject_key_rows,
        legacy_trace_subject_rows,
        legacy_memory_item_rows,
        legacy_run_memory_binding_rows,
        binding_backfill_digest,
        cutover_finite,
        ingress_finite,
        activated_finite,
        first_activity_finite,
        rollback_finite,
        binding_digest_valid,
    ) = row
    if (cutover_finite, ingress_finite, activated_finite, first_activity_finite, rollback_finite) != (
        True,
        True,
        True,
        True,
        True,
    ):
        raise RuntimeError("tracebed erasure cutover state is invalid")
    if not isinstance(cutover_at, datetime) or not isinstance(ingress_attested_at, datetime):
        raise RuntimeError("tracebed erasure cutover state is invalid")
    if any(value is not None and not isinstance(value, datetime) for value in (activated_at, first_activity_at, rollback_at)):
        raise RuntimeError("tracebed erasure cutover state is invalid")
    if (
        any(type(value) is not int or value < 0 for value in (
            legacy_subject_key_rows,
            legacy_trace_subject_rows,
            legacy_memory_item_rows,
            legacy_run_memory_binding_rows,
        ))
        or binding_digest_valid is not True
        or not isinstance(binding_backfill_digest, bytes)
        or len(binding_backfill_digest) != 32
    ):
        raise RuntimeError("tracebed erasure cutover state is invalid")
    state = _ErasureCutoverActivationState(
        cutover_at,
        ingress_attested_at,
        activated_at,
        first_activity_at,
        rollback_at,
        legacy_subject_key_rows,
        legacy_trace_subject_rows,
        legacy_memory_item_rows,
        legacy_run_memory_binding_rows,
        binding_backfill_digest,
    )
    if state.ingress_attested_at != state.cutover_at:
        raise RuntimeError("tracebed erasure cutover ingress receipt is invalid")
    if state.activated_at is not None and state.activated_at < state.cutover_at:
        raise RuntimeError("tracebed erasure cutover state is invalid")
    if state.first_activity_at is not None and (
        state.activated_at is None or state.first_activity_at < state.activated_at
    ):
        raise RuntimeError("tracebed erasure cutover state is invalid")
    if state.rollback_quarantined_at is not None and (
        state.activated_at is None
        or state.rollback_quarantined_at < state.activated_at
        or state.first_activity_at is not None
    ):
        raise RuntimeError("tracebed erasure cutover state is invalid")
    return state


def _erasure_cutover_activation_state(
    conn: psycopg.Connection[Any], *, for_update: bool = False
) -> _ErasureCutoverActivationState:
    """Read (and, for a transition, lock) the exact c12 singleton receipt."""

    suffix = " FOR UPDATE" if for_update else ""
    try:
        with conn.cursor() as cursor:
            cursor.execute(_ERASURE_CUTOVER_ACTIVATION_STATE_SQL + suffix)
            row = cursor.fetchone()
    except psycopg.Error as exc:
        raise RuntimeError("tracebed erasure cutover state is invalid") from exc
    return _decode_erasure_cutover_activation_state(row)


def _ensure_erasure_cutover_drained(conn: psycopg.Connection[Any]) -> None:
    """Prove the stricter c12 migration drain before touching its schema."""

    try:
        with conn.cursor() as cursor:
            cursor.execute(_ERASURE_CUTOVER_DRAIN_SQL)
            row = cursor.fetchone()
    except psycopg.Error as exc:
        raise RuntimeError("tracebed erasure cutover requires a drained runtime") from exc
    if row != (True,):
        raise RuntimeError("tracebed erasure cutover requires a drained runtime")


def _ensure_erasure_deployment_drained(conn: psycopg.Connection[Any]) -> None:
    """Require zero authenticated E4 sessions and no live executor lease."""

    if not _erasure_deployment_present(conn):
        raise RuntimeError("tracebed erasure deployment is absent")
    try:
        with conn.cursor() as cursor:
            cursor.execute(_ERASURE_DEPLOYMENT_DRAIN_SQL)
            row = cursor.fetchone()
    except psycopg.Error as exc:
        raise RuntimeError("tracebed erasure deployment requires a drained runtime") from exc
    if row != (True,):
        raise RuntimeError("tracebed erasure deployment requires a drained runtime")


def _erasure_deployment_state(conn: psycopg.Connection[Any], *, for_update: bool = False) -> tuple[
    datetime, datetime | None, datetime | None, datetime | None
]:
    """Read the E4 staged/publication/activity state with finite timestamps."""

    suffix = " FOR UPDATE" if for_update else ""
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT staged_at, activated_at, first_executor_activity_at, rollback_quarantined_at, "
                "isfinite(staged_at), activated_at IS NULL OR isfinite(activated_at), "
                "first_executor_activity_at IS NULL OR isfinite(first_executor_activity_at), "
                "rollback_quarantined_at IS NULL OR isfinite(rollback_quarantined_at) "
                "FROM public.erasure_deployment_state WHERE singleton" + suffix
            )
            row = cursor.fetchone()
    except psycopg.Error as exc:
        raise RuntimeError("tracebed erasure deployment state is invalid") from exc
    if (
        row is None
        or len(row) != 8
        or not isinstance(row[0], datetime)
        or not all(value is True for value in row[4:])
        or any(value is not None and not isinstance(value, datetime) for value in row[1:4])
    ):
        raise RuntimeError("tracebed erasure deployment state is invalid")
    staged, activated, first_activity, rollback_at = row[:4]
    if (
        (activated is not None and activated < staged)
        or (first_activity is not None and (activated is None or first_activity < activated))
        or (rollback_at is not None and (activated is None or rollback_at < activated))
    ):
        raise RuntimeError("tracebed erasure deployment state is invalid")
    return staged, activated, first_activity, rollback_at


def _expected_yoyo_history(
    tip: Literal[
        "0010_authority_foundation",
        "0011_authority_cutover",
        "0012_erasure_saga",
        "0013_erasure_deployment",
    ]
) -> tuple[tuple[str, str], ...]:
    """Return the only accepted ordered yoyo history for a cutover action."""

    if tip == "0013_erasure_deployment":
        return _YOYO_MIGRATION_HISTORY
    if tip == "0012_erasure_saga":
        return _YOYO_MIGRATION_HISTORY[:-1]
    if tip == "0011_authority_cutover":
        # E1 is intentionally unreleased and no 0011 lifecycle action may
        # silently cross its new erasure receipt.  Keep the established c11
        # action boundary exact while retaining 0012's hash for its own
        # foundation/rollback verifier.
        return _YOYO_MIGRATION_HISTORY[:-2]
    return _YOYO_MIGRATION_HISTORY[:-3]


def _ensure_exact_yoyo_history(
    conn: psycopg.Connection[Any],
    *,
    tip: Literal[
        "0010_authority_foundation",
        "0011_authority_cutover",
        "0012_erasure_saga",
        "0013_erasure_deployment",
    ],
) -> None:
    """Authenticate yoyo 9's real tracking schema and its ordered history.

    ``current_revision()`` only intersects yoyo's tracking rows with the
    packaged migration set.  That means it can hide an extra or forged row;
    rollback must instead inspect the actual yoyo 9 table and require every
    expected row, hash, and strictly increasing apply receipt.
    """

    with conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT column_name, data_type, character_maximum_length, is_nullable
              FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = '_yoyo_migration'
             ORDER BY ordinal_position
            """
        )
        columns = cursor.fetchall()
        try:
            cursor.execute(
                """
                SELECT migration_id, migration_hash, applied_at_utc, isfinite(applied_at_utc)
                  FROM public._yoyo_migration
                 ORDER BY applied_at_utc, migration_id, migration_hash
                """
            )
            rows = cursor.fetchall()
        except psycopg.Error as exc:
            # psycopg cannot decode PostgreSQL +/-infinity timestamps. An
            # unrepresentable yoyo receipt is forged history, not a safe
            # reason to proceed with a rollback quarantine.
            raise RuntimeError("tracebed rollback action requires the exact yoyo migration history") from exc
    if tuple(columns) != _YOYO_MIGRATION_COLUMNS:
        raise RuntimeError("tracebed rollback action requires the exact yoyo 9 migration schema")
    expected = _expected_yoyo_history(tip)
    if len(rows) != len(expected):
        raise RuntimeError("tracebed rollback action requires the exact yoyo migration history")
    previous_applied_at: datetime | None = None
    for row, expected_row in zip(rows, expected, strict=True):
        if not isinstance(row, tuple) or len(row) != 4:
            raise RuntimeError("tracebed rollback action requires the exact yoyo migration history")
        migration_id, migration_hash, applied_at_utc, applied_at_finite = row
        if (
            (migration_id, migration_hash) != expected_row
            or not isinstance(applied_at_utc, datetime)
            or applied_at_finite is not True
            or (previous_applied_at is not None and applied_at_utc <= previous_applied_at)
        ):
            raise RuntimeError("tracebed rollback action requires the exact yoyo migration history")
        previous_applied_at = applied_at_utc


def _quarantine_split_roles(conn: psycopg.Connection[Any]) -> None:
    """Atomically return both staged credentials to an unusable state."""

    with conn.transaction(), conn.cursor() as cursor:
        for role_name, _ in _SPLIT_ROLES:
            cursor.execute(sql.SQL("ALTER ROLE {} NOLOGIN PASSWORD NULL").format(sql.Identifier(role_name)))
        for role_name, _ in _SPLIT_ROLES:
            cursor.execute(_SPLIT_ROLE_STATE_SQL, (role_name,))
            state = cursor.fetchone()
            if state is None or state[0] is not False:
                raise RuntimeError("tracebed split role quarantine failed")
            cursor.execute("SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = %s", (role_name,))
            password_row = cursor.fetchone()
            if password_row != (True,):
                raise RuntimeError("tracebed split role quarantine failed")


def _ensure_ingress_quarantine_attested_session(conn: psycopg.Connection[Any]) -> None:
    """Require the trusted owner connection's explicit external-fence assertion."""

    with conn.cursor() as cursor:
        cursor.execute("SELECT current_setting(%s, true) = 'on'", (_INGRESS_QUARANTINED_GUC,))
        row = cursor.fetchone()
    if row != (True,):
        raise RuntimeError("tracebed rollback requires an externally quarantined ingress")


def _ensure_split_roles_quarantined_for_rollback(conn: psycopg.Connection[Any]) -> None:
    """Require NOLOGIN split identities while retaining their genuine SCRAMs."""

    expected_state = (False, False, False, False, True, False, False, -1, True, True)
    for role_name, group_name in _SPLIT_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_SPLIT_ROLE_STATE_SQL, (role_name,))
            state = cursor.fetchone()
            cursor.execute(_SPLIT_ROLE_MEMBERSHIPS_SQL, (role_name,))
            memberships = cursor.fetchall()
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
            membership_count = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (role_name,))
            ownership_count = cursor.fetchone()
            cursor.execute(_SPLIT_ROLE_AUTH_SQL, (role_name,))
            auth = cursor.fetchone()
        if state != expected_state or memberships != [(group_name, False, True, False)]:
            raise RuntimeError("tracebed split role is not safely quarantined for rollback")
        if membership_count != (1,) or ownership_count != (0,) or auth != (True, True):
            raise RuntimeError("tracebed split role is not safely quarantined for rollback")
        if not _protected_role_acls_are_clean(conn, role_name, legacy_app=False):
            raise RuntimeError("tracebed split role retains unsafe authority dependencies")


def _ensure_rollback_cutover_fence(
    conn: psycopg.Connection[Any], *, split_roles_quarantined: bool
) -> None:
    """Validate the complete active/quarantined cutover surface without repair."""

    _ensure_ingress_quarantine_attested_session(conn)
    _ensure_dedicated_cluster_inventory(conn)
    _ensure_prepared_transactions_clean(conn)
    _ensure_protected_role_settings_clean(conn)
    _ensure_authority_epoch_profile_current(conn)
    _ensure_legacy_app_quarantined_shape(conn)
    if not _protected_role_acls_are_clean(conn, APP_ROLE, legacy_app=False):
        raise RuntimeError("tracebed legacy application role retains unsafe access dependencies")
    _ensure_cutover_foundation_group_fence(conn)
    if split_roles_quarantined:
        _ensure_split_roles_quarantined_for_rollback(conn)
    else:
        _ensure_split_roles_active(conn)
        for role_name, _ in _SPLIT_ROLES:
            if not _protected_role_acls_are_clean(conn, role_name, legacy_app=False):
                raise RuntimeError("tracebed split role retains unsafe authority dependencies")


def _rollback_quarantine_barrier() -> None:
    """Narrow test seam while the singleton receipt lock is held."""


def quarantine_authority_cutover_for_rollback(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    app_password: str,
    api_password: str,
    worker_password: str,
) -> None:
    """Commit/retry an ingress-attested NOLOGIN quarantine before 0011 rollback.

    The receipt is committed before any termination or physical credential
    probe. Every later failure deliberately leaves all three identities
    disabled and the marker in place, so a retry can finish safely without a
    compensating LOGIN transition.
    """

    with conn.transaction():
        # This is the actual yoyo 9 table, not yoyo's filtered revision API.
        # Take its lock before trusting the history or touching a role, so an
        # inserted/missing/forged row cannot race a durable quarantine.
        with conn.cursor() as cursor:
            cursor.execute("LOCK TABLE public._yoyo_migration IN ACCESS EXCLUSIVE MODE")
        _ensure_exact_yoyo_history(conn, tip="0011_authority_cutover")
        with conn.cursor() as cursor:
            state = _locked_cutover_activation_state(cursor)
            if state.activated_at is None or state.first_activity_at is not None:
                raise RuntimeError("tracebed authority cutover cannot be quarantined for rollback")
            if state.rollback_quarantined_at is None:
                _ensure_rollback_cutover_fence(conn, split_roles_quarantined=False)
                _rollback_quarantine_barrier()
                for role_name in (APP_ROLE, API_ROLE, WORKER_ROLE):
                    cursor.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(role_name)))
                cursor.execute(
                    "UPDATE public.authority_cutover_state "
                    "SET rollback_quarantined_at = statement_timestamp() "
                    "WHERE singleton AND rollback_quarantined_at IS NULL "
                    "RETURNING rollback_quarantined_at"
                )
                marker = cursor.fetchone()
                if marker is None or len(marker) != 1 or not isinstance(marker[0], datetime):
                    raise RuntimeError("tracebed authority rollback quarantine receipt update failed")
                _ensure_rollback_cutover_fence(conn, split_roles_quarantined=True)
            else:
                # A prior attempt may have died after its committed fence but
                # before yoyo completed. Treat it as a retry only when all role,
                # profile, and receipt evidence still has the safe exact shape.
                _ensure_rollback_cutover_fence(conn, split_roles_quarantined=True)

    _terminate_runtime_role_sessions(conn, (APP_ROLE, API_ROLE, WORKER_ROLE))
    for role_name, password in (
        (APP_ROLE, app_password),
        (API_ROLE, api_password),
        (WORKER_ROLE, worker_password),
    ):
        _require_credential_rejected(owner_dsn, role_name, password, permit_disabled_role=True)
    _ensure_no_runtime_sessions(conn)
    state = _cutover_activation_state(conn)
    if state.activated_at is None or state.first_activity_at is not None or state.rollback_quarantined_at is None:
        raise RuntimeError("tracebed authority rollback quarantine receipt is invalid")
    _ensure_rollback_cutover_fence(conn, split_roles_quarantined=True)


def _is_expected_startup_rejection(
    exc: psycopg.OperationalError, role_name: str, *, permit_disabled_role: bool
) -> bool:
    """Classify only PostgreSQL's authentication/NOLOGIN startup rejections.

    libpq does not reliably retain ``ErrorResponse`` fields while a connection
    is starting, hence the narrowly enumerated rendering fallback.  A timeout,
    TLS/HBA proxy failure, shutdown, or arbitrary text must remain an operator
    visible infrastructure failure rather than being mistaken for a safe
    negative credential probe.
    """

    sqlstate = exc.sqlstate or getattr(getattr(exc, "diag", None), "sqlstate", None)
    # A server-provided SQLSTATE is authoritative.  In particular, never let
    # a shutdown, connection, or resource error carrying auth-looking proxy
    # text fall through to the rendering fallback below.  PG18 reports
    # password failure as 28P01 and a NOLOGIN startup rejection as 28000.
    if sqlstate is not None:
        return sqlstate == "28P01" or (permit_disabled_role and sqlstate == "28000")
    message = str(exc).replace("\r\n", "\n")
    normalized = message.rstrip("\n")
    # psycopg/libpq's synchronous startup path often prefixes the exact
    # server ErrorResponse with the selected TCP endpoint.  Permit only that
    # documented wrapper, retaining the literal PostgreSQL FATAL payload and
    # target role.  Do not accept an unwrapped or generic substring: either
    # form could be produced by a proxy or transport failure with no SQLSTATE.
    payloads = [f'password authentication failed for user "{role_name}"']
    if permit_disabled_role:
        payloads.append(f'role "{role_name}" is not permitted to log in')
    if any(
        re.fullmatch(
            r'connection failed: connection to server at "[^"\n]+", port [0-9]+ failed: '
            + r'FATAL:  '
            + re.escape(payload),
            normalized,
        )
        is not None
        for payload in payloads
    ):
        return True
    # Compose-v1 intentionally provides no HBA line for the retired
    # ``tracebed_app`` login. This narrowly recognizes that exact closed
    # network proof only after the owner connection has live-attested the
    # complete profile; a generic HBA rejection can never count as a safe
    # credential probe.
    return (
        permit_disabled_role
        and role_name == APP_ROLE
        and re.fullmatch(
            r"connection failed: connection to server at \""
            + re.escape(_COMPOSE_ADMIN_POSTGRES_IP)
            + r'\", port 5432 failed: FATAL:  pg_hba\.conf rejects connection for host \"'
            + re.escape(_COMPOSE_ADMIN_CLIENT_IP)
            + r'\", user \"tracebed_app\", database \"tracebed\", no encryption',
            normalized,
        )
        is not None
    )


def _require_credential_rejected(
    owner_dsn: str, role_name: str, password: str, *, permit_disabled_role: bool
) -> None:
    """Physically prove a configured credential cannot authenticate.

    This deliberately does not accept a generic ``OperationalError``: only a
    PostgreSQL password/NOLOGIN rejection is proof that the ingress fence is
    holding.  Everything else propagates unchanged.
    """

    try:
        with psycopg.connect(_split_role_probe_dsn(owner_dsn, role_name, password)):
            pass
    except psycopg.OperationalError as exc:
        if _is_expected_startup_rejection(exc, role_name, permit_disabled_role=permit_disabled_role):
            return
        raise
    raise RuntimeError("tracebed credential unexpectedly authenticated during authority quarantine")


def _ensure_legacy_app_quarantined_shape(conn: psycopg.Connection[Any]) -> None:
    """Require the exact disabled legacy identity expected by 0011."""

    with conn.cursor() as cursor:
        cursor.execute(_ROLE_STATE_SQL, (APP_ROLE,))
        state = cursor.fetchone()
        cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (APP_ROLE,))
        memberships = cursor.fetchone()
        cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (APP_ROLE,))
        ownership = cursor.fetchone()
        cursor.execute(_SPLIT_ROLE_AUTH_SQL, (APP_ROLE,))
        auth = cursor.fetchone()
    if (
        state != (False, False, False, False, False, False, False, -1, False, True)
        or memberships != (0,)
        or ownership != (0,)
        or auth != (True, True)
    ):
        raise RuntimeError("tracebed legacy application role is not safely quarantined")


def quarantine_legacy_app_for_cutover(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    app_password: str,
    ingress_quarantined: bool,
) -> None:
    """Commit the legacy ``NOLOGIN`` fence required before direct 0011 DDL.

    PostgreSQL role DDL cannot stop a connection which authenticated before the
    transaction commits.  The caller therefore supplies an explicit external
    ingress-fence attestation.  That assertion is required even if the legacy
    role is already ``NOLOGIN``: an already-authenticated backend survives
    role DDL until explicitly terminated and physically checked.
    """

    if ingress_quarantined is not True:
        raise RuntimeError("tracebed 0011 requires an externally quarantined legacy ingress")
    with conn.transaction(), conn.cursor() as cursor:
        cursor.execute(_ROLE_EXISTS_SQL, (APP_ROLE,))
        if cursor.fetchone() != (True,):
            raise RuntimeError("tracebed legacy application role is missing")
        cursor.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(APP_ROLE)))
        cursor.execute("SELECT NOT rolcanlogin FROM pg_roles WHERE rolname = %s", (APP_ROLE,))
        if cursor.fetchone() != (True,):
            raise RuntimeError("tracebed legacy application quarantine failed")
    _ensure_legacy_app_quarantined_shape(conn)
    _terminate_runtime_role_sessions(conn, (APP_ROLE,))
    _ensure_no_runtime_sessions(conn)
    _require_credential_rejected(
        owner_dsn, APP_ROLE, app_password, permit_disabled_role=True
    )
    _ensure_legacy_app_quarantined_shape(conn)
    _ensure_no_runtime_sessions(conn)


def _split_role_probe_dsn(owner_dsn: str, role_name: str, password: str) -> str:
    """Build a bounded credential probe on its one permitted Compose route."""

    fields = conninfo_to_dict(owner_dsn)
    host = fields.get("host")
    probe_host: str | None = None
    if host == _COMPOSE_ADMIN_HOST:
        if role_name == API_ROLE:
            probe_host = _COMPOSE_API_HOST
        elif role_name == WORKER_ROLE:
            probe_host = _COMPOSE_WORKER_HOST
        elif _CREDENTIAL_PROBE_NAME_RE.fullmatch(role_name) is not None:
            probe_host = _COMPOSE_PROBE_HOST
    route = {"host": probe_host} if probe_host is not None else {}

    return make_conninfo(
        owner_dsn,
        user=role_name,
        password=password,
        connect_timeout="5",
        application_name="tracebed-bootstrap-probe",
        **route,
    )


def _inspect_credential_probe(
    cursor: psycopg.Cursor[Any], probe_role: str, *, must_be_expired: bool
) -> bool:
    """Read and validate a probe without changing its session or catalog.

    ``True`` means the role exists and has the one exact probe shape.  A
    near-prefix name is deliberately ignored: it is not a capability minted by
    this bootstrap protocol.  Every exact nonce candidate is checked before
    cleanup can terminate even one backend.
    """

    if _CREDENTIAL_PROBE_NAME_RE.fullmatch(probe_role) is None:
        return False
    cursor.execute(_ROLE_EXISTS_SQL, (probe_role,))
    exists = cursor.fetchone()
    if exists == (False,):
        return False
    if exists != (True,):
        raise RuntimeError("database returned an invalid credential probe lookup")
    cursor.execute(_ROLE_STATE_SQL, (probe_role,))
    state = cursor.fetchone()
    cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (probe_role,))
    memberships = cursor.fetchone()
    cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (probe_role,))
    ownership = cursor.fetchone()
    cursor.execute(_FOUNDATION_ROLE_UNSAFE_ACL_COUNT_SQL, (probe_role,))
    unsafe_acl = cursor.fetchone()
    cursor.execute(
        "SELECT rolconfig IS NULL AND NOT EXISTS ("
        "SELECT 1 FROM pg_db_role_setting AS setting "
        "JOIN pg_roles AS role ON role.oid = setting.setrole WHERE role.rolname = %s"
        ") FROM pg_roles WHERE rolname = %s",
        (probe_role, probe_role),
    )
    settings_clean = cursor.fetchone()
    expiration_predicate = (
        "rolvaliduntil IS NOT NULL AND rolvaliduntil < clock_timestamp()"
        if must_be_expired
        else "rolvaliduntil IS NOT NULL AND rolvaliduntil <= clock_timestamp() + interval '10 minutes'"
    )
    cursor.execute(
        f"SELECT {expiration_predicate} FROM pg_authid WHERE rolname = %s",  # noqa: S608 -- fixed SQL
        (probe_role,),
    )
    expiry = cursor.fetchone()
    cursor.execute(
        "SELECT auth.rolpassword LIKE 'SCRAM-SHA-256$%%', "
        "description.description = %s "
        "FROM pg_authid AS auth "
        "LEFT JOIN pg_shdescription AS description "
        "ON description.objoid = auth.oid AND description.classoid = 'pg_authid'::regclass "
        "WHERE auth.rolname = %s",
        (_CREDENTIAL_PROBE_COMMENT, probe_role),
    )
    marker = cursor.fetchone()
    # The capability may have one direct ACL only: non-delegable CONNECT on
    # this database, granted by its owner.  This is a positive assertion, not
    # a temporary broad REVOKE that might hide a hostile dependency.
    cursor.execute(
        "SELECT count(*) = 1 AND bool_and("
        "database.datname = current_database() AND privilege.privilege_type = 'CONNECT' "
        "AND NOT privilege.is_grantable AND privilege.grantor = database.datdba"
        ") FROM pg_database AS database "
        "CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) "
        "AS privilege JOIN pg_roles AS grantee ON grantee.oid = privilege.grantee "
        "WHERE grantee.rolname = %s",
        (probe_role,),
    )
    exact_connect = cursor.fetchone()
    cursor.execute(
        "SELECT count(*) = 1 AND bool_and("
        "dependency.classid = 'pg_database'::regclass "
        "AND dependency.objid = (SELECT oid FROM pg_database WHERE datname = current_database()) "
        "AND dependency.deptype = 'a'"
        ") FROM pg_shdepend AS dependency JOIN pg_roles AS role "
        "ON role.oid = dependency.refobjid "
        "WHERE role.rolname = %s AND dependency.refclassid = 'pg_authid'::regclass",
        (probe_role,),
    )
    exact_dependency = cursor.fetchone()
    if (
        state is None
        or len(state) != 10
        or tuple(state[:8]) != (True, False, False, False, False, False, False, 1)
        or state[8] is not False
        or state[9] is not False
        or memberships != (0,)
        or ownership != (0,)
        or unsafe_acl != (0,)
        or settings_clean != (True,)
        or expiry != (True,)
        or marker != (True, True)
        or exact_connect != (True,)
        or exact_dependency != (True,)
    ):
        raise RuntimeError("tracebed credential probe has unsafe state")
    return True


def _credential_probe_termination_results(
    cursor: psycopg.Cursor[Any], probe_role: str
) -> list[tuple[Any, ...]]:
    """Request bounded termination and return every PostgreSQL result row.

    This narrow seam makes a failed termination observable before any catalog
    revoke/drop.  The caller, rather than this helper, decides whether every
    returned row is the required literal ``true``.
    """

    cursor.execute(
        "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity "
        "WHERE pid <> pg_backend_pid() AND usename = %s",
        (probe_role,),
    )
    return cursor.fetchall()


def _ensure_credential_probe_sessions_terminated(
    cursor: psycopg.Cursor[Any], probe_role: str
) -> None:
    """Require true termination results and a fresh, bounded zero-session read."""

    results = _credential_probe_termination_results(cursor, probe_role)
    if any(len(row) != 1 or row[0] is not True for row in results):
        raise RuntimeError("tracebed credential probe session termination failed")

    # pg_stat_activity can retain a transaction-local statistics snapshot.
    # Clear it before *every* post-termination count, retrying once without a
    # sleep so a delayed backend remains a refusal rather than a blind wait.
    for _ in range(2):
        cursor.execute("SELECT pg_stat_clear_snapshot()")
        cursor.fetchone()
        cursor.execute(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE pid <> pg_backend_pid() AND usename = %s",
            (probe_role,),
        )
        count = cursor.fetchone()
        if (
            count is None
            or len(count) != 1
            or not isinstance(count[0], int)
            or isinstance(count[0], bool)
            or count[0] < 0
        ):
            raise RuntimeError("database returned an invalid credential probe session count")
        if count[0] == 0:
            return
    raise RuntimeError("tracebed credential probe retains a runtime session")


def _drop_validated_credential_probe(cursor: psycopg.Cursor[Any], probe_role: str) -> None:
    """Terminate and remove one probe only after a complete inspection pass."""

    _ensure_credential_probe_sessions_terminated(cursor, probe_role)
    cursor.execute(
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
            sql.Identifier(cursor.connection.info.dbname), sql.Identifier(probe_role)
        )
    )
    cursor.execute(sql.SQL("DROP ROLE {} ").format(sql.Identifier(probe_role)))


def _drop_credential_probe(conn: psycopg.Connection[Any], probe_role: str) -> None:
    """Clean up one known current-run nonce; it may not have expired yet."""

    if _CREDENTIAL_PROBE_NAME_RE.fullmatch(probe_role) is None:
        raise RuntimeError("invalid tracebed credential probe identity")
    with conn.transaction(), conn.cursor() as cursor:
        if _inspect_credential_probe(cursor, probe_role, must_be_expired=False):
            _drop_validated_credential_probe(cursor, probe_role)


def _cleanup_stale_credential_probes(conn: psycopg.Connection[Any]) -> None:
    """Atomically remove only exact, already-expired bootstrap probe roles."""

    with conn.transaction(), conn.cursor() as cursor:
        cursor.execute(
            "SELECT rolname FROM pg_roles "
            "WHERE left(rolname, length(%s)) = %s ORDER BY rolname",
            (_CREDENTIAL_PROBE_PREFIX, _CREDENTIAL_PROBE_PREFIX),
        )
        candidates: list[str] = []
        for row in cursor.fetchall():
            if len(row) != 1 or not isinstance(row[0], str):
                raise RuntimeError("database returned an invalid credential probe identity")
            # Near-prefix identities are not bootstrap capabilities.  They
            # are neither terminated nor dropped, even when benign.
            if _CREDENTIAL_PROBE_NAME_RE.fullmatch(row[0]) is None:
                continue
            if _inspect_credential_probe(cursor, row[0], must_be_expired=True):
                candidates.append(row[0])
        # No server-side termination happens before every candidate has been
        # fully validated.  Catalog rollback cannot undo termination, so this
        # ordering is the atomicity boundary that matters.
        for probe_role in candidates:
            _drop_validated_credential_probe(cursor, probe_role)


def _prepare_credential_probe(
    conn: psycopg.Connection[Any], *, owner_dsn: str, password: str
) -> tuple[str, str]:
    """Physically authenticate an ephemeral role and return its SCRAM verifier.

    The real API/worker identities remain ``NOLOGIN`` and passwordless during
    this operation.  A fresh nonce role receives only CONNECT on the already
    hardened current database; once its supplied secret is proven usable, its
    verifier is copied under owner control and the role is removed before any
    runtime identity is published.
    """

    expected_database = conninfo_to_dict(owner_dsn).get("dbname")
    if not isinstance(expected_database, str) or not expected_database:
        raise RuntimeError("tracebed owner connection has no database name")
    if password.startswith("SCRAM-SHA-256$"):
        raise ConfigError("split database passwords must be cleartext credentials")
    probe_role = f"{_CREDENTIAL_PROBE_PREFIX}{uuid4().hex}"
    try:
        with conn.transaction(), conn.cursor() as cursor:
            cursor.execute("SET LOCAL password_encryption = 'scram-sha-256'")
            # Probe expiry is issued from the same database clock used by the
            # stale-probe validator. Host clock skew must not strand a freshly
            # authenticated bootstrap-owned role as "unsafe" residue.
            cursor.execute(
                "SELECT clock_timestamp() + make_interval(secs => %s)",
                (_CREDENTIAL_PROBE_LIFETIME_SECONDS,),
            )
            valid_until_row = cursor.fetchone()
            if (
                valid_until_row is None
                or len(valid_until_row) != 1
                or not isinstance(valid_until_row[0], datetime)
            ):
                raise RuntimeError("database returned an invalid credential probe expiry")
            valid_until = valid_until_row[0]
            cursor.execute(
                _role_statement(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOINHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT 1",
                    probe_role,
                    password,
                )
            )
            cursor.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(expected_database), sql.Identifier(probe_role)
                )
            )
            cursor.execute(
                sql.SQL("ALTER ROLE {} VALID UNTIL {}").format(
                    sql.Identifier(probe_role), sql.Literal(valid_until.isoformat())
                )
            )
            cursor.execute(
                sql.SQL("COMMENT ON ROLE {} IS {}").format(
                    sql.Identifier(probe_role), sql.Literal(_CREDENTIAL_PROBE_COMMENT)
                )
            )
        with psycopg.connect(_split_role_probe_dsn(owner_dsn, probe_role, password)) as probe:
            with probe.cursor() as cursor:
                cursor.execute(
                    "SELECT session_user, current_database(), "
                    "has_database_privilege(session_user, current_database(), 'CONNECT'), "
                    "has_database_privilege(session_user, current_database(), 'TEMP'), "
                    "has_schema_privilege(session_user, 'public', 'CREATE')"
                )
                row = cursor.fetchone()
            if row != (probe_role, expected_database, True, False, False):
                raise RuntimeError("tracebed credential probe failed")
        with conn.cursor() as cursor:
            cursor.execute("SELECT rolpassword FROM pg_authid WHERE rolname = %s", (probe_role,))
            verifier = cursor.fetchone()
        if (
            verifier is None
            or len(verifier) != 1
            or not isinstance(verifier[0], str)
            or not verifier[0].startswith("SCRAM-SHA-256$")
        ):
            raise RuntimeError("tracebed credential probe did not produce a SCRAM verifier")
        return probe_role, verifier[0]
    except Exception:
        _drop_credential_probe(conn, probe_role)
        raise


def _require_distinct_probe_credentials(
    owner_dsn: str,
    *,
    api_probe_role: str,
    api_password: str,
    worker_probe_role: str,
    worker_password: str,
) -> None:
    """Reject SASLprep-equivalent secrets before either runtime role is published."""

    for role_name, other_password in (
        (api_probe_role, worker_password),
        (worker_probe_role, api_password),
    ):
        try:
            with psycopg.connect(_split_role_probe_dsn(owner_dsn, role_name, other_password)):
                pass
        except psycopg.OperationalError as exc:
            if _is_expected_startup_rejection(exc, role_name, permit_disabled_role=False):
                continue
            raise
        raise ConfigError("split database passwords must remain distinct after PostgreSQL normalization")


def _set_split_role_verifier(cursor: psycopg.Cursor[Any], role_name: str, verifier: str) -> None:
    """Install a verified SCRAM verifier without ever reusing a cleartext secret."""

    cursor.execute(
        _role_statement(
            "ALTER ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "INHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1",
            role_name,
            verifier,
        )
    )


def _probe_activated_split_role(owner_dsn: str, role_name: str, password: str) -> None:
    """Verify supplied credentials after an already-published activation only."""

    expected_database = conninfo_to_dict(owner_dsn).get("dbname")
    if not isinstance(expected_database, str) or not expected_database:
        raise RuntimeError("tracebed owner connection has no database name")
    expected_group = dict(_SPLIT_ROLES)[role_name]
    with psycopg.connect(_split_role_probe_dsn(owner_dsn, role_name, password)) as probe, probe.cursor() as cursor:
        cursor.execute(
            "SELECT session_user, current_database(), "
            "has_database_privilege(session_user, current_database(), 'CONNECT'), "
            "has_database_privilege(session_user, current_database(), 'TEMP'), "
            "has_schema_privilege(session_user, 'public', 'CREATE'), "
            "pg_has_role(session_user, %s, 'member')",
            (expected_group,),
        )
        row = cursor.fetchone()
    # c12 deliberately removes raw work-queue access and replaces it with
    # SECURITY DEFINER queue operations.  This probe is only the physical
    # credential/HBA identity proof; the signed epoch profile authenticates
    # the role's actual capability surface separately.
    if row != (role_name, expected_database, True, False, False, True):
        raise RuntimeError("tracebed split role credential probe failed")


def _ensure_cutover_foundation_groups(
    conn: psycopg.Connection[Any], *, e4_deployment: bool = False
) -> None:
    """Validate group roles including the one E4 executor membership when present."""

    expected_state = (False, False, False, False, False, False, False, -1, True, True)
    expected_memberships = {
        "tracebed_api_group": (1,),
        "tracebed_worker_group": (1,),
        "tracebed_erasure_group": (1 if e4_deployment else 0,),
    }
    for role_name in FOUNDATION_GROUP_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_ROLE_STATE_SQL, (role_name,))
            state = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (role_name,))
            membership_count = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (role_name,))
            ownership_count = cursor.fetchone()
        if (
            state != expected_state
            or membership_count != expected_memberships[role_name]
            or ownership_count != (0,)
        ):
            raise RuntimeError("tracebed foundation group has unsafe authority dependencies")


def _ensure_cutover_foundation_group_fence(
    conn: psycopg.Connection[Any], *, e4_deployment: bool = False
) -> None:
    """Read the exact group surface, including only E4's reviewed executor edge."""

    _ensure_cutover_foundation_groups(conn, e4_deployment=e4_deployment)
    expected_edges = {
        "tracebed_api_group": [
            ("tracebed_api_group", API_ROLE, False, True, False),
        ],
        "tracebed_worker_group": [
            ("tracebed_worker_group", WORKER_ROLE, False, True, False),
        ],
        "tracebed_erasure_group": (
            [("tracebed_erasure_group", ERASURE_ROLE, False, True, False)]
            if e4_deployment
            else []
        ),
    }
    for role_name in FOUNDATION_GROUP_ROLES:
        with conn.cursor() as cursor:
            cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_EDGES_SQL, (role_name, role_name))
            membership_edges = cursor.fetchall()
            cursor.execute(_FOUNDATION_ROLE_UNSAFE_ACL_COUNT_SQL, (role_name,))
            unsafe_acl = cursor.fetchone()
            cursor.execute(_FOUNDATION_ROLE_NON_ACL_DEPENDENCY_COUNT_SQL, (role_name,))
            dependencies = cursor.fetchone()
        if membership_edges != expected_edges[role_name]:
            raise RuntimeError("tracebed foundation group has unsafe authority dependencies")
        if unsafe_acl != (0,) or dependencies != (0,):
            raise RuntimeError("tracebed foundation group has unsafe authority dependencies")


def _ensure_existing_cutover_non_split_fence(
    conn: psycopg.Connection[Any],
) -> _CutoverActivationState:
    """Read every protected non-split fact before residue recovery can mutate.

    A marker-null cutover can contain a safe interrupted split publication. It
    must *not* make the legacy identity, a foundation group, the authenticated
    profile, or the receipt less authoritative. This gate performs only
    catalog reads (and the profile's security-definer assertions) and leaves
    split role attributes, verifiers, and sessions untouched on every
    failure. The split-only classifier is intentionally called by the caller
    only after this complete non-split fence succeeds.
    """

    _ensure_dedicated_cluster_inventory(conn)
    _ensure_prepared_transactions_clean(conn)
    _ensure_protected_role_settings_clean(conn)
    e4_deployment = _erasure_deployment_present(conn)
    if e4_deployment:
        # E4 intentionally replaces c12's erasure-login-absent tuple.  Its
        # deployment receipt, rather than the now-superseded c12 catalog
        # digest, is the authenticated lifecycle fence from this point on.
        _ensure_e4_receipt(conn)
    else:
        _ensure_authority_epoch_profile_current(conn)
    _cutover_state_validation_barrier()
    state = _cutover_activation_state(conn)

    _ensure_legacy_app_quarantined_shape(conn)
    if not _protected_role_acls_are_clean(conn, APP_ROLE, legacy_app=False):
        raise RuntimeError("tracebed legacy application role retains unsafe access dependencies")
    _ensure_no_legacy_app_sessions(conn)

    _ensure_cutover_foundation_group_fence(conn, e4_deployment=e4_deployment)
    return state


def _locked_cutover_activation_state(cursor: psycopg.Cursor[Any]) -> _CutoverActivationState:
    """Lock the singleton receipt before a publication decision is made."""

    try:
        cursor.execute(_CUTOVER_ACTIVATION_STATE_SQL + " FOR UPDATE")
        row = cursor.fetchone()
    except psycopg.Error as exc:
        # psycopg rejects PostgreSQL +/-infinity while decoding. Treat an
        # unrepresentable cutover receipt as unsafe evidence, never as a
        # transport error that would permit a caller to continue.
        raise RuntimeError("tracebed authority cutover state is invalid") from exc
    return _decode_cutover_activation_state(row)


def _ensure_cutover_publication_fence(conn: psycopg.Connection[Any]) -> None:
    """Revalidate every authority prerequisite immediately before LOGIN.

    The profile assertion authenticates the full ACL/schema/dependency matrix.
    This companion covers fields intentionally absent from a catalog ACL hash:
    server inventory, role attributes, credential state, membership direction,
    ownership, activity receipt, and surviving authenticated backends.
    """

    state = _ensure_existing_cutover_non_split_fence(conn)
    if (
        state.activated_at is not None
        or state.first_activity_at is not None
        or state.rollback_quarantined_at is not None
    ):
        raise RuntimeError("tracebed authority cutover is not in a publishable state")
    ensure_split_roles_pre_activation(conn)
    _ensure_no_runtime_sessions(conn)


def _activation_publication_barrier() -> None:
    """Narrow test seam for mutations injected between credential probes and CAS."""


def _recover_marker_null_split_residue(conn: psycopg.Connection[Any]) -> None:
    """Quarantine only the narrow safe residue class before a fresh attempt."""

    publication_state = _classify_split_role_publication(conn)
    if publication_state in {"active", "residue"} or _split_role_sessions_present(conn):
        _quarantine_split_roles(conn)
        _terminate_split_role_sessions(conn)
    _ensure_no_runtime_sessions(conn)


def _activate_split_roles(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    api_password: str,
    worker_password: str,
    compose_v1: bool,
) -> None:
    """Atomically make both staged split roles credential-bearing logins.

    The explicit transaction is intentionally narrower than bootstrap's session
    advisory lock.  A failure after the first ``ALTER ROLE`` rolls both changes
    back, so there is no period in which only one half of the cutover can run.
    """

    state = _ensure_existing_cutover_non_split_fence(conn)
    if state.rollback_quarantined_at is not None:
        raise RuntimeError("tracebed authority cutover is quarantined for rollback")
    publication_state = _classify_split_role_publication(conn)
    if state.activated_at is not None:
        if publication_state != "active":
            raise RuntimeError("tracebed activated cutover has disabled split roles")
        _ensure_split_roles_active(conn)
        try:
            _probe_activated_split_role(owner_dsn, API_ROLE, api_password)
            _probe_activated_split_role(owner_dsn, WORKER_ROLE, worker_password)
            _require_distinct_probe_credentials(
                owner_dsn,
                api_probe_role=API_ROLE,
                api_password=api_password,
                worker_probe_role=WORKER_ROLE,
                worker_password=worker_password,
            )
            # Final active-retry source proof: a prior successful bootstrap
            # must not mask a later reordered/relaxed HBA file.
            if compose_v1:
                attest_compose_v1_hba(conn, reload=False)
            return
        except Exception:
            _quarantine_split_roles(conn)
            _terminate_split_role_sessions(conn)
            raise
    if publication_state in {"active", "residue"} or _split_role_sessions_present(conn):
        # A process died after committing LOGIN but before marking activation.
        # Quarantine both credentials together *before* checking sessions.
        # A held pre-crash session otherwise prevents recovery forever even
        # though NOLOGIN does not evict it.  Once both names are disabled,
        # terminate every split backend and require a clean global runtime set
        # before the new receipt/credentials can be published.
        _recover_marker_null_split_residue(conn)
    else:
        _ensure_no_runtime_sessions(conn)
    probe_roles: list[str] = []
    try:
        api_probe_role, api_verifier = _prepare_credential_probe(
            conn, owner_dsn=owner_dsn, password=api_password
        )
        probe_roles.append(api_probe_role)
        worker_probe_role, worker_verifier = _prepare_credential_probe(
            conn, owner_dsn=owner_dsn, password=worker_password
        )
        probe_roles.append(worker_probe_role)
        _require_distinct_probe_credentials(
            owner_dsn,
            api_probe_role=api_probe_role,
            api_password=api_password,
            worker_probe_role=worker_probe_role,
            worker_password=worker_password,
        )
    finally:
        for probe_role in reversed(probe_roles):
            _drop_credential_probe(conn, probe_role)
    _activation_publication_barrier()
    with conn.transaction(), conn.cursor() as cursor:
        # Lock the singleton first.  Every deployment-sensitive predicate is
        # repeated after the probe connections have closed and immediately
        # before the two verifiers become usable.
        state = _locked_cutover_activation_state(cursor)
        if (
            state.activated_at is not None
            or state.first_activity_at is not None
            or state.rollback_quarantined_at is not None
        ):
            raise RuntimeError("tracebed authority cutover is not in a publishable state")
        _ensure_cutover_publication_fence(conn)
        # This attestation is intentionally *inside* the final activation
        # transaction, after the singleton receipt lock and immediately before
        # verifier/LOGIN publication.  ``reload=False`` proves the currently
        # loaded rules rather than reloading a mutable host mount here.
        if compose_v1:
            attest_compose_v1_hba(conn, reload=False)
        _set_split_role_verifier(cursor, API_ROLE, api_verifier)
        _set_split_role_verifier(cursor, WORKER_ROLE, worker_verifier)
        _ensure_split_roles_active(conn)
        cursor.execute(
            """
            UPDATE public.authority_cutover_state
               SET activated_at = clock_timestamp()
             WHERE singleton
               AND activated_at IS NULL
               AND first_activity_at IS NULL
               AND rollback_quarantined_at IS NULL
            RETURNING activated_at
            """
        )
        row = cursor.fetchone()
        if row is None or len(row) != 1:
            raise RuntimeError("tracebed authority activation receipt update failed")
    try:
        # A post-commit physical path catches any HBA/file drift that occurred
        # between the in-transaction proof and published credentials.  A
        # failure quarantines *both* identities and evicts held sessions.
        if compose_v1:
            attest_compose_v1_hba(conn, reload=False)
        _probe_activated_split_role(owner_dsn, API_ROLE, api_password)
        _probe_activated_split_role(owner_dsn, WORKER_ROLE, worker_password)
        _require_distinct_probe_credentials(
            owner_dsn,
            api_probe_role=API_ROLE,
            api_password=api_password,
            worker_probe_role=WORKER_ROLE,
            worker_password=worker_password,
        )
    except Exception:
        _quarantine_split_roles(conn)
        _terminate_split_role_sessions(conn)
        raise


def _rollback_0011_from_quarantine(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    app_password: str,
    api_password: str,
    worker_password: str,
    compose_v1: bool,
) -> None:
    """Run exactly the one permitted 0011 rollback after a durable fence."""

    # The quarantine helper authenticates yoyo 9's actual tracking table
    # while holding it against concurrent history changes.  Do not use
    # ``current_revision()`` here: it filters unknown rows out of its result.
    # Re-attest at the exact owner-side rollback boundary.  Once quarantine
    # commits both runtime logins are NOLOGIN and their sessions are gone, so
    # the subsequent separate yoyo connection cannot publish an old route.
    if compose_v1:
        attest_compose_v1_hba(conn, reload=False)
    quarantine_authority_cutover_for_rollback(
        conn,
        owner_dsn=owner_dsn,
        app_password=app_password,
        api_password=api_password,
        worker_password=worker_password,
    )
    rolled_back = rollback_migrations(owner_dsn)
    if rolled_back != ["0011_authority_cutover"]:
        raise RuntimeError("tracebed rollback action requires exactly the applied 0011 cutover")
    _ensure_exact_yoyo_history(conn, tip="0010_authority_foundation")


def _run_authority_admission_action(
    conn: psycopg.Connection[Any],
    *,
    action: Literal[
        "admission-close", "admission-open", "runtime-drain-assert", "admission-assert-closed"
    ],
) -> None:
    """Execute one closed owner-only admission/drain transition.

    The SQL functions own the singleton row locking and caller boundary.  This
    wrapper first authenticates the already-active profile so a controller can
    never use lifecycle plumbing to reach a drifted cutover catalog.
    """

    state = _ensure_existing_cutover_non_split_fence(conn)
    if state.activated_at is None or state.rollback_quarantined_at is not None:
        raise RuntimeError("tracebed authority cutover is not active for lifecycle action")
    if _erasure_deployment_present(conn):
        _ensure_e4_receipt(conn)
    else:
        _ensure_authority_epoch_profile_current(conn)
    function_name = {
        _BOOTSTRAP_ADMISSION_CLOSE_ACTION: "tracebed_close_authority_admission",
        _BOOTSTRAP_ADMISSION_OPEN_ACTION: "tracebed_open_authority_admission",
        _BOOTSTRAP_RUNTIME_DRAIN_ASSERT_ACTION: "tracebed_assert_authority_runtime_drained",
        _BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION: "tracebed_assert_authority_admission_closed",
    }[action]
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT public.{function_name}()")


def _ensure_c11_ready_for_erasure_cutover(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    api_password: str,
    worker_password: str,
    compose_v1: bool,
) -> None:
    """Authenticate the closed-world c11 source before an E2 transition."""

    state = _ensure_existing_cutover_non_split_fence(conn)
    if state.activated_at is None or state.rollback_quarantined_at is not None:
        raise RuntimeError("tracebed authority cutover is not active for erasure cutover")
    _ensure_latest_authority_epoch_profile(conn, expected="cutover_0011")
    _ensure_exact_yoyo_history(conn, tip="0011_authority_cutover")
    # This is an active-retry proof only: it performs physical credential/HBA
    # probes but cannot publish a new role because the c11 receipt is already
    # active. Prove it before closing admission, so a bad runtime credential
    # does not turn an otherwise healthy c11 deployment into a stopped one.
    _activate_split_roles(
        conn,
        owner_dsn=owner_dsn,
        api_password=api_password,
        worker_password=worker_password,
        compose_v1=compose_v1,
    )


def _close_and_drain_for_erasure_cutover(conn: psycopg.Connection[Any]) -> None:
    """Close c11 admission and prove the stricter c12 migration drain."""

    _run_authority_admission_action(conn, action=_BOOTSTRAP_ADMISSION_CLOSE_ACTION)
    _run_authority_admission_action(conn, action=_BOOTSTRAP_RUNTIME_DRAIN_ASSERT_ACTION)
    _ensure_erasure_cutover_drained(conn)


def _activate_erasure_cutover_if_pending(conn: psycopg.Connection[Any]) -> bool:
    """CAS the c12 singleton while retaining the closed-admission fence.

    The authority admission assertion takes a SHARE lock on the singleton for
    this complete transaction. An owner-side open requires UPDATE, so it
    cannot race from the c11 drain receipt to E2 activation.
    """

    with conn.transaction():
        with conn.cursor() as cursor:
            cursor.execute("LOCK TABLE public._yoyo_migration IN ACCESS EXCLUSIVE MODE")
        _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
        _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
        with conn.cursor() as cursor:
            cursor.execute("SELECT public.tracebed_assert_authority_admission_closed()")
        _ensure_erasure_cutover_drained(conn)
        state = _erasure_cutover_activation_state(conn, for_update=True)
        if state.rollback_quarantined_at is not None or state.first_activity_at is not None:
            raise RuntimeError("tracebed erasure cutover is not in an activatable state")
        if state.activated_at is not None:
            return False
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE public.erasure_cutover_state
                   SET activated_at = clock_timestamp()
                 WHERE singleton
                   AND activated_at IS NULL
                   AND first_activity_at IS NULL
                   AND rollback_quarantined_at IS NULL
                RETURNING activated_at
                """
            )
            row = cursor.fetchone()
        if row is None or len(row) != 1 or not isinstance(row[0], datetime):
            raise RuntimeError("tracebed erasure activation receipt update failed")
    return True


def _cutover_0012(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    api_password: str,
    worker_password: str,
    compose_v1: bool,
    open_admission: bool = True,
) -> None:
    """Apply and activate E2 only through the explicit closed/drained path."""

    if _erasure_deployment_present(conn):
        # An E4 upgrade republishes the already-authenticated deployment; it
        # must not try to re-enter c12's erasure-login-absent profile after
        # the executor has recorded activity.  The controller has stopped
        # the executor first, so retain c13 only after independently proving
        # its exact history, receipt, closed admission, and drain boundary.
        _ensure_exact_yoyo_history(conn, tip="0013_erasure_deployment")
        _ensure_e4_receipt(conn)
        _staged, activated_at, _first_activity, rollback_at = _erasure_deployment_state(conn)
        if activated_at is None or rollback_at is not None:
            raise RuntimeError("tracebed erasure deployment is not active for republish")
        _run_authority_admission_action(conn, action=_BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION)
        _ensure_erasure_deployment_drained(conn)
        return

    if not _erasure_cutover_present(conn):
        _ensure_c11_ready_for_erasure_cutover(
            conn,
            owner_dsn=owner_dsn,
            api_password=api_password,
            worker_password=worker_password,
            compose_v1=compose_v1,
        )
        _close_and_drain_for_erasure_cutover(conn)
        applied = apply_migrations(owner_dsn)
        if applied != ["0012_erasure_saga"]:
            raise RuntimeError("tracebed erasure cutover requires exactly the pending 0012 migration")
        ensure_schema_current(conn)
    else:
        # A failed attempt after the migration receipt but before singleton
        # activation is safely retryable only from the exact c12 catalog.
        state = _ensure_existing_cutover_non_split_fence(conn)
        if state.activated_at is None or state.rollback_quarantined_at is not None:
            raise RuntimeError("tracebed authority cutover is not active for erasure cutover")
        _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
        _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
        erasure_state = _erasure_cutover_activation_state(conn)
        if erasure_state.rollback_quarantined_at is not None:
            raise RuntimeError("tracebed erasure cutover is quarantined for rollback")
        if erasure_state.activated_at is not None:
            # Do not turn an explicit lifecycle retry into an implicit reopen
            # after an operator intentionally closed admission for maintenance.
            return
        _close_and_drain_for_erasure_cutover(conn)

    _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
    erasure_state = _erasure_cutover_activation_state(conn)
    if erasure_state.rollback_quarantined_at is not None:
        raise RuntimeError("tracebed erasure cutover is quarantined for rollback")
    activated = _activate_erasure_cutover_if_pending(conn)
    if activated and open_admission:
        # The receipt commits before publication. Once admission opens, c12
        # runtime readiness requires both the authority and erasure receipts.
        _run_authority_admission_action(conn, action=_BOOTSTRAP_ADMISSION_OPEN_ACTION)


def _erasure_role_probe_dsn(
    owner_dsn: str, password: str, *, cross_route: bool = False
) -> str:
    """Build the sole E4 credential probe route, never a caller supplied DSN."""

    fields = conninfo_to_dict(owner_dsn)
    route: dict[str, str] = {}
    if fields.get("host") == _COMPOSE_ADMIN_HOST:
        route["host"] = _COMPOSE_API_HOST if cross_route else _COMPOSE_ERASURE_HOST
    return make_conninfo(
        owner_dsn,
        user=ERASURE_ROLE,
        password=password,
        connect_timeout="5",
        application_name="tracebed-erasure-bootstrap-probe",
        **route,
    )


def _erasure_role_state_is_active(conn: psycopg.Connection[Any]) -> bool:
    """Validate only the published E4 LOGIN shape and its one membership."""

    with conn.cursor() as cursor:
        cursor.execute(_ROLE_STATE_SQL, (ERASURE_ROLE,))
        state = cursor.fetchone()
        cursor.execute(_SPLIT_ROLE_MEMBERSHIPS_SQL, (ERASURE_ROLE,))
        memberships = cursor.fetchall()
        cursor.execute(_FOUNDATION_ROLE_MEMBERSHIP_COUNT_SQL, (ERASURE_ROLE,))
        membership_count = cursor.fetchone()
        cursor.execute(_FOUNDATION_ROLE_OWNERSHIP_COUNT_SQL, (ERASURE_ROLE,))
        ownership_count = cursor.fetchone()
        cursor.execute(
            "SELECT rolconfig IS NULL AND NOT EXISTS ("
            "SELECT 1 FROM pg_db_role_setting AS setting "
            "JOIN pg_roles AS role ON role.oid = setting.setrole "
            "WHERE role.rolname = %s) FROM pg_roles WHERE rolname = %s",
            (ERASURE_ROLE, ERASURE_ROLE),
        )
        settings_clean = cursor.fetchone()
    return (
        state == (True, False, False, False, True, False, False, -1, False, True)
        and memberships == [("tracebed_erasure_group", False, True, False)]
        and membership_count == (1,)
        and ownership_count == (0,)
        and settings_clean == (True,)
    )


def _set_erasure_role_verifier(cursor: psycopg.Cursor[Any], verifier: str) -> None:
    """Publish precisely the staged E4 role shape with a verified SCRAM hash."""

    cursor.execute(
        _role_statement(
            "ALTER ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "INHERIT NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1",
            ERASURE_ROLE,
            verifier,
        )
    )
    cursor.execute(sql.SQL("ALTER ROLE {} RESET ALL").format(sql.Identifier(ERASURE_ROLE)))


def _terminate_erasure_role_sessions(conn: psycopg.Connection[Any]) -> None:
    """Terminate only the staged runtime identity after it is quarantined."""

    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity "
            "WHERE pid <> pg_backend_pid() AND usename = %s",
            (ERASURE_ROLE,),
        )
        results = cursor.fetchall()
    if any(len(row) != 1 or row[0] is not True for row in results):
        raise RuntimeError("tracebed erasure session termination failed")
    for _ in range(2):
        with conn.cursor() as cursor:
            cursor.execute("SELECT pg_stat_clear_snapshot()")
            cursor.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE pid <> pg_backend_pid() AND usename = %s",
                (ERASURE_ROLE,),
            )
            row = cursor.fetchone()
        if row == (0,):
            return
    raise RuntimeError("tracebed erasure session termination failed")


def _quarantine_erasure_publication(
    conn: psycopg.Connection[Any], *, owner_dsn: str, password: str
) -> None:
    """Make a marker-null partial publication inert before a retry."""

    with conn.transaction(), conn.cursor() as cursor:
        cursor.execute(
            sql.SQL("ALTER ROLE {} NOLOGIN PASSWORD NULL").format(sql.Identifier(ERASURE_ROLE))
        )
        cursor.execute(sql.SQL("ALTER ROLE {} RESET ALL").format(sql.Identifier(ERASURE_ROLE)))
    _terminate_erasure_role_sessions(conn)
    try:
        with psycopg.connect(_erasure_role_probe_dsn(owner_dsn, password)):
            pass
    except psycopg.OperationalError as exc:
        if _is_expected_startup_rejection(exc, ERASURE_ROLE, permit_disabled_role=True):
            return
        raise
    raise RuntimeError("tracebed erasure quarantine left a usable login")


def _probe_activated_erasure_role(owner_dsn: str, password: str) -> None:
    """Prove the E4 own-route credential, then both independent negative routes."""

    expected_database = conninfo_to_dict(owner_dsn).get("dbname")
    if not isinstance(expected_database, str) or not expected_database:
        raise RuntimeError("tracebed owner connection has no database name")
    with psycopg.connect(_erasure_role_probe_dsn(owner_dsn, password)) as probe, probe.cursor() as cursor:
        cursor.execute(
            "SELECT session_user, current_database(), "
            "has_database_privilege(session_user, current_database(), 'CONNECT'), "
            "has_database_privilege(session_user, current_database(), 'TEMP'), "
            "has_schema_privilege(session_user, 'public', 'CREATE'), "
            "pg_has_role(session_user, 'tracebed_erasure_group', 'member')"
        )
        row = cursor.fetchone()
    if row != (ERASURE_ROLE, expected_database, True, False, False, True):
        raise RuntimeError("tracebed erasure own-route credential probe failed")


def _require_erasure_cross_probes(owner_dsn: str, *, erasure_password: str, api_password: str) -> None:
    """Reject a cross credential and a cross subnet after E4 publication."""

    probes = [_erasure_role_probe_dsn(owner_dsn, api_password)]
    if conninfo_to_dict(owner_dsn).get("host") == _COMPOSE_ADMIN_HOST:
        probes.append(_erasure_role_probe_dsn(owner_dsn, erasure_password, cross_route=True))
    for dsn in probes:
        try:
            with psycopg.connect(dsn):
                pass
        except psycopg.OperationalError:
            continue
        raise RuntimeError("tracebed erasure cross-route or cross-credential probe authenticated")


def _ensure_e4_receipt(conn: psycopg.Connection[Any]) -> None:
    """Authenticate E4 after c12's erasure-absent profile has intentionally changed."""

    if not _erasure_deployment_present(conn):
        raise RuntimeError("tracebed erasure deployment is absent")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT public.erasure_deployment_security_assert()")
            row = cursor.fetchone()
    except psycopg.Error as exc:
        raise RuntimeError("tracebed erasure deployment receipt is invalid") from exc
    if row is None or len(row) != 1 or not isinstance(row[0], bytes) or len(row[0]) != 32:
        raise RuntimeError("tracebed erasure deployment receipt is invalid")


def _activate_erasure_deployment(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    erasure_password: str,
    api_password: str,
    compose_v1: bool,
) -> None:
    """Publish E4 only after HBA and physical own/cross route proofs.

    The activation receipt is deliberately written last.  If a process dies
    after ``LOGIN`` commits, a later invocation observes its null marker,
    revokes it to ``NOLOGIN PASSWORD NULL``, terminates old sessions, and
    starts a fresh verifier/probe cycle.
    """

    _ensure_exact_yoyo_history(conn, tip="0013_erasure_deployment")
    _ensure_e4_receipt(conn)
    _staged_at, activated_at, first_activity, rollback_at = _erasure_deployment_state(conn)
    if rollback_at is not None:
        raise RuntimeError("tracebed erasure deployment is quarantined for rollback")
    if activated_at is not None:
        if first_activity is not None:
            # It is an active deployed executor, never a bootstrap retry
            # surface.  The controller's upgrade path owns recovery.
            return
        if not _erasure_role_state_is_active(conn):
            raise RuntimeError("tracebed erasure activation receipt has disabled login")
        if compose_v1:
            attest_compose_v1_hba(conn, reload=False)
        _probe_activated_erasure_role(owner_dsn, erasure_password)
        _require_erasure_cross_probes(
            owner_dsn, erasure_password=erasure_password, api_password=api_password
        )
        return

    if _erasure_role_state_is_active(conn):
        _quarantine_erasure_publication(conn, owner_dsn=owner_dsn, password=erasure_password)
    else:
        _ensure_erasure_deployment_drained(conn)

    probe_role: str | None = None
    try:
        probe_role, verifier = _prepare_credential_probe(
            conn, owner_dsn=owner_dsn, password=erasure_password
        )
    finally:
        if probe_role is not None:
            _drop_credential_probe(conn, probe_role)
    with conn.transaction(), conn.cursor() as cursor:
        _staged_at, activated_at, first_activity, rollback_at = _erasure_deployment_state(
            conn, for_update=True
        )
        if activated_at is not None or first_activity is not None or rollback_at is not None:
            raise RuntimeError("tracebed erasure deployment is not publishable")
        if compose_v1:
            attest_compose_v1_hba(conn, reload=False)
        _set_erasure_role_verifier(cursor, verifier)
        if not _erasure_role_state_is_active(conn):
            raise RuntimeError("tracebed erasure activation role shape is invalid")
        _ensure_e4_receipt(conn)
    try:
        if compose_v1:
            attest_compose_v1_hba(conn, reload=False)
        _probe_activated_erasure_role(owner_dsn, erasure_password)
        _require_erasure_cross_probes(
            owner_dsn, erasure_password=erasure_password, api_password=api_password
        )
    except Exception:
        _quarantine_erasure_publication(conn, owner_dsn=owner_dsn, password=erasure_password)
        raise
    with conn.transaction(), conn.cursor() as cursor:
        _staged_at, activated_at, first_activity, rollback_at = _erasure_deployment_state(
            conn, for_update=True
        )
        if activated_at is not None or first_activity is not None or rollback_at is not None:
            raise RuntimeError("tracebed erasure deployment is not publishable")
        cursor.execute(
            "UPDATE public.erasure_deployment_state SET activated_at = clock_timestamp() "
            "WHERE singleton AND activated_at IS NULL AND first_executor_activity_at IS NULL "
            "AND rollback_quarantined_at IS NULL RETURNING activated_at"
        )
        row = cursor.fetchone()
        if row is None or len(row) != 1 or not isinstance(row[0], datetime):
            raise RuntimeError("tracebed erasure activation receipt update failed")


def _cutover_0013(
    conn: psycopg.Connection[Any],
    *,
    owner_dsn: str,
    erasure_password: str,
    api_password: str,
    compose_v1: bool,
) -> None:
    """Apply/stage E4 from the exact closed c12 state, then publish LOGIN."""

    if not _erasure_deployment_present(conn):
        _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
        _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
        _run_authority_admission_action(conn, action=_BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION)
        _ensure_erasure_cutover_drained(conn)
        applied = apply_migrations(owner_dsn, through="0013_erasure_deployment")
        if applied != ["0013_erasure_deployment"]:
            raise RuntimeError("tracebed erasure deployment requires exactly pending 0013 migration")
        ensure_schema_current(conn)
    _activate_erasure_deployment(
        conn,
        owner_dsn=owner_dsn,
        erasure_password=erasure_password,
        api_password=api_password,
        compose_v1=compose_v1,
    )


def _rollback_0013_from_quarantine(conn: psycopg.Connection[Any], *, owner_dsn: str) -> None:
    """Rollback E4 only before the first executor mutation/claim."""

    _run_authority_admission_action(conn, action=_BOOTSTRAP_ADMISSION_CLOSE_ACTION)
    _ensure_erasure_deployment_drained(conn)
    _staged_at, activated_at, first_activity, rollback_at = _erasure_deployment_state(conn)
    if activated_at is None or first_activity is not None:
        raise RuntimeError("tracebed erasure deployment rollback is refused after executor activity")
    if rollback_at is not None:
        raise RuntimeError("tracebed erasure deployment rollback is already quarantined")
    rolled_back = rollback_migrations(owner_dsn)
    if rolled_back != ["0013_erasure_deployment"]:
        raise RuntimeError("tracebed rollback action requires exactly the applied 0013 deployment")
    _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
    _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")


def _authenticate_active_0013_rollback_refusal_recovery(
    conn: psycopg.Connection[Any],
) -> None:
    """Certify the only active-E4 state safe to hand back to ``upgrade``.

    A failed owner-side rollback is normally ambiguous: it could have failed
    before, during, or after the yoyo transition, so the controller must not
    recreate a runtime identity on its strength alone.  The post-activity
    refusal is the one deliberate exception.  It leaves 0013 applied, the
    deployment receipt intact, the executor published, and admission closed.
    Authenticate every one of those durable facts before restoring the sole
    closed ordinary worker for the next supported controller ``upgrade``.
    """

    _ensure_exact_yoyo_history(conn, tip="0013_erasure_deployment")
    _ensure_e4_receipt(conn)
    _staged_at, activated_at, first_activity_at, rollback_at = _erasure_deployment_state(conn)
    if activated_at is None or first_activity_at is None or rollback_at is not None:
        raise RuntimeError("tracebed active erasure rollback refusal is not recoverable")
    _ensure_split_roles_active(conn)
    if not _erasure_role_state_is_active(conn):
        raise RuntimeError("tracebed active erasure rollback refusal has disabled login")
    _run_authority_admission_action(conn, action=_BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION)


def quarantine_erasure_cutover_for_rollback(conn: psycopg.Connection[Any]) -> None:
    """Commit the c12 preactivity quarantine before the one permitted rollback."""

    with conn.transaction():
        with conn.cursor() as cursor:
            cursor.execute("LOCK TABLE public._yoyo_migration IN ACCESS EXCLUSIVE MODE")
        _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
        _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
        authority_state = _ensure_existing_cutover_non_split_fence(conn)
        if authority_state.activated_at is None or authority_state.rollback_quarantined_at is not None:
            raise RuntimeError("tracebed authority cutover is not active for erasure rollback")
        with conn.cursor() as cursor:
            cursor.execute("SELECT public.tracebed_assert_authority_runtime_drained()")
        _ensure_erasure_cutover_drained(conn)
        state = _erasure_cutover_activation_state(conn, for_update=True)
        if state.activated_at is None or state.first_activity_at is not None:
            raise RuntimeError("tracebed erasure cutover cannot be quarantined for rollback")
        if state.rollback_quarantined_at is None:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE public.erasure_cutover_state
                       SET rollback_quarantined_at = statement_timestamp()
                     WHERE singleton
                       AND rollback_quarantined_at IS NULL
                       AND first_activity_at IS NULL
                    RETURNING rollback_quarantined_at
                    """
                )
                row = cursor.fetchone()
            if row is None or len(row) != 1 or not isinstance(row[0], datetime):
                raise RuntimeError("tracebed erasure rollback quarantine receipt update failed")


def _rollback_0012_from_quarantine(conn: psycopg.Connection[Any], *, owner_dsn: str) -> None:
    """Rollback exactly c12 after a durable closed/drained preactivity fence."""

    _close_and_drain_for_erasure_cutover(conn)
    quarantine_erasure_cutover_for_rollback(conn)
    rolled_back = rollback_migrations(owner_dsn)
    if rolled_back != ["0012_erasure_saga"]:
        raise RuntimeError("tracebed rollback action requires exactly the applied 0012 erasure cutover")
    _ensure_exact_yoyo_history(conn, tip="0011_authority_cutover")
    _ensure_latest_authority_epoch_profile(conn, expected="cutover_0011")
    if _erasure_cutover_present(conn):
        raise RuntimeError("tracebed erasure rollback left a cutover receipt behind")


def bootstrap_database(
    owner_dsn: str,
    app_password: str,
    api_password: str,
    worker_password: str,
    cluster_scope: str,
    *,
    erasure_password: object = "",
    ingress_quarantined: bool = False,
    hba_profile: object | None = None,
    action: object = _BOOTSTRAP_APPLY_ACTION,
) -> None:
    """Harden the app role, apply packaged migrations, and repair live partitions.

    A session advisory lock spans every stage.  ``apply_migrations`` obtains
    yoyo's own backend lock as well, while this fixed lock serializes the
    broader role/DDL sequence across multiple one-shot bootstrap containers.
    """
    # Nothing cluster-global (including stale probe cleanup) may happen until
    # all credentials, the dedicated-cluster assertion, and the independent
    # ingress attestation have passed.  The latter is intentionally required
    # for every bootstrap invocation; it is an operator assertion, not a
    # claim that PostgreSQL can inspect firewall/HBA state.
    action = _validate_bootstrap_action(action)
    compose_v1 = hba_profile == COMPOSE_V1_PROFILE
    if hba_profile is not None and not compose_v1:
        raise ConfigError("compose-v1 HBA profile is required")
    owner_dsn, app_password, api_password, worker_password = _validate_authority_inputs(
        owner_dsn,
        app_password,
        api_password,
        worker_password,
        cluster_scope,
        ingress_quarantined=ingress_quarantined,
    )
    if action == _BOOTSTRAP_CUTOVER_0013_ACTION:
        erasure_password = _require_cleartext_credential(erasure_password, _ERASURE_PASSWORD_ENV)
    elif erasure_password not in ("", None):
        # A supplied value is still validated even for c11/c12-only actions;
        # this prevents a malformed mounted secret from becoming invisible on
        # the first E4 activation attempt.
        erasure_password = _require_cleartext_credential(erasure_password, _ERASURE_PASSWORD_ENV)
    else:
        erasure_password = ""
    migration_dsn = _dedicated_cluster_dsn(
        owner_dsn, cluster_scope, ingress_quarantined=True
    )

    with psycopg.connect(migration_dsn, autocommit=True) as conn:
        locked = False
        try:
            with conn.cursor() as cursor:
                cursor.execute(_LOCK_SQL, (BOOTSTRAP_LOCK_KEY,))
                # Bootstrap is an owner-side security path.  Do not inherit a
                # deployment-controlled "$user",public path while validating
                # or repairing the authority surface.
                cursor.execute("SET search_path = pg_catalog, public")
            locked = True
            if compose_v1:
                attest_compose_v1_hba(conn, reload=True)
            if action in (
                _BOOTSTRAP_ADMISSION_CLOSE_ACTION,
                _BOOTSTRAP_ADMISSION_OPEN_ACTION,
                _BOOTSTRAP_RUNTIME_DRAIN_ASSERT_ACTION,
                _BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION,
            ):
                # Read the checked HBA source a second time at the exact
                # lifecycle transition.  It makes a host-side HBA drift a
                # fail-closed owner operation rather than a stale startup
                # attestation.
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                if action == _BOOTSTRAP_ADMISSION_OPEN_ACTION:
                    if _erasure_deployment_present(conn):
                        _ensure_exact_yoyo_history(conn, tip="0013_erasure_deployment")
                        _ensure_e4_receipt(conn)
                        _staged, activated, _first, rollback_at = _erasure_deployment_state(conn)
                        if activated is None or rollback_at is not None:
                            raise RuntimeError("tracebed erasure deployment is not active for admission open")
                    elif _erasure_cutover_present(conn):
                        _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
                        _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
                        erasure_state = _erasure_cutover_activation_state(conn)
                        if (
                            erasure_state.activated_at is None
                            or erasure_state.rollback_quarantined_at is not None
                        ):
                            raise RuntimeError("tracebed erasure cutover is not active for admission open")
                _run_authority_admission_action(conn, action=action)
                return
            if action == _BOOTSTRAP_ERASURE_DRAIN_ASSERT_ACTION:
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                if _erasure_deployment_present(conn):
                    _ensure_exact_yoyo_history(conn, tip="0013_erasure_deployment")
                    _ensure_e4_receipt(conn)
                    _ensure_erasure_deployment_drained(conn)
                else:
                    # A supported c12 rollback has no E4 LOGIN to drain.
                    # Keep the controller's fixed service stop usable on that
                    # authenticated history, while the later c12 rollback
                    # branch performs its stricter queue/runtime drain.
                    _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
                    _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
                    if conn.execute(
                        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles "
                        "WHERE rolname = 'tracebed_erasure') OR EXISTS ("
                        "SELECT 1 FROM pg_catalog.pg_stat_activity "
                        "WHERE pid <> pg_catalog.pg_backend_pid() "
                        "AND usename = 'tracebed_erasure')"
                    ).fetchone() != (False,):
                        raise RuntimeError("tracebed c12 erasure deployment residue is unsafe")
                return
            if action == _BOOTSTRAP_START_PREFLIGHT_ACTION:
                # A true zero-state first start has no cutover objects yet;
                # it can still prove no split runtime session exists before
                # image build or any migration mutation.  Once 0011 exists,
                # the owner-only drain assertion additionally authenticates
                # the exact active/profiled, closed admission receipt.
                if _cutover_present(conn):
                    if compose_v1:
                        attest_compose_v1_hba(conn, reload=False)
                    _run_authority_admission_action(
                        conn, action=_BOOTSTRAP_RUNTIME_DRAIN_ASSERT_ACTION
                    )
                elif conn.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity "
                    "WHERE pid <> pg_catalog.pg_backend_pid() "
                    "AND usename IN ('tracebed_api', 'tracebed_worker'))"
                ).fetchone() != (False,):
                    raise RuntimeError("tracebed start preflight requires no runtime sessions")
                return
            if action == _BOOTSTRAP_ROLLBACK_RECOVERY_PREFLIGHT_ACTION:
                # This is the only controller-supported bridge from a
                # successful E4 rollback back to publication.  It rejects a
                # merely stopped E4 runtime: recovery must be the exact
                # authenticated c12 history with no residual E4 login before
                # the controller drains its restored ordinary worker.
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
                _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
                if conn.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles "
                    "WHERE rolname = 'tracebed_erasure') OR EXISTS ("
                    "SELECT 1 FROM pg_catalog.pg_stat_activity "
                    "WHERE pid <> pg_catalog.pg_backend_pid() "
                    "AND usename = 'tracebed_erasure')"
                ).fetchone() != (False,):
                    raise RuntimeError("tracebed rollback recovery contains erasure residue")
                _run_authority_admission_action(
                    conn, action=_BOOTSTRAP_ADMISSION_CLOSED_ASSERT_ACTION
                )
                return
            if action == _BOOTSTRAP_ROLLBACK_REFUSAL_RECOVERY_PREFLIGHT_ACTION:
                # Unlike a generic owner-call failure, a post-activity 0013
                # rollback refusal is a defined non-mutating outcome.  The
                # controller may recreate its closed drain worker only after
                # this independent proof rules out a partial/ambiguous yoyo
                # transition and certifies the still-active E4 receipt.
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _authenticate_active_0013_rollback_refusal_recovery(conn)
                return
            if action == _BOOTSTRAP_CUTOVER_0012_ACTION:
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _cutover_0012(
                    conn,
                    owner_dsn=migration_dsn,
                    api_password=api_password,
                    worker_password=worker_password,
                    compose_v1=compose_v1,
                )
                return
            if action == _BOOTSTRAP_CUTOVER_0012_CLOSED_ACTION:
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _cutover_0012(
                    conn,
                    owner_dsn=migration_dsn,
                    api_password=api_password,
                    worker_password=worker_password,
                    compose_v1=compose_v1,
                    open_admission=False,
                )
                _run_authority_admission_action(conn, action=_BOOTSTRAP_ADMISSION_CLOSE_ACTION)
                return
            if action == _BOOTSTRAP_CUTOVER_0013_ACTION:
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _cutover_0013(
                    conn,
                    owner_dsn=migration_dsn,
                    erasure_password=erasure_password,
                    api_password=api_password,
                    compose_v1=compose_v1,
                )
                return
            if action == _BOOTSTRAP_ROLLBACK_ACTION:
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                if _erasure_deployment_present(conn):
                    _rollback_0013_from_quarantine(conn, owner_dsn=migration_dsn)
                elif _erasure_cutover_present(conn):
                    _rollback_0012_from_quarantine(conn, owner_dsn=migration_dsn)
                else:
                    _rollback_0011_from_quarantine(
                        conn,
                        owner_dsn=migration_dsn,
                        app_password=app_password,
                        api_password=api_password,
                        worker_password=worker_password,
                        compose_v1=compose_v1,
                    )
                return
            if action == _BOOTSTRAP_ROLLBACK_0013_ACTION:
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _rollback_0013_from_quarantine(conn, owner_dsn=migration_dsn)
                return
            if action == _BOOTSTRAP_ROLLBACK_0012_ACTION:
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _rollback_0012_from_quarantine(conn, owner_dsn=migration_dsn)
                return
            if action == _BOOTSTRAP_ROLLBACK_0011_ACTION:
                # No stale-probe cleanup, yoyo apply, partition repair, or
                # activation may run on this branch. The quarantine commits
                # first; a yoyo failure is therefore intentionally retryable
                # only from the same NOLOGIN receipt state.
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _rollback_0011_from_quarantine(
                    conn,
                    owner_dsn=migration_dsn,
                    app_password=app_password,
                    api_password=api_password,
                    worker_password=worker_password,
                    compose_v1=compose_v1,
                )
                return
            # These are evidence-only stop-the-world checks.  In particular,
            # a fifth database or prepared transaction must not cause stale
            # probe cleanup to mutate any cluster-global role first.
            _ensure_dedicated_cluster_inventory(conn)
            _ensure_prepared_transactions_clean(conn)
            _ensure_protected_role_settings_clean(conn)
            cutover_before = _cutover_present(conn)
            if cutover_before and _erasure_deployment_present(conn):
                # E4 intentionally invalidates c12's erasure-login-absent
                # catalog profile.  An ordinary bootstrap retry therefore
                # validates the successor receipt rather than attempting to
                # repair or re-run the accepted c12 surface.
                _ensure_exact_yoyo_history(conn, tip="0013_erasure_deployment")
                _ensure_e4_receipt(conn)
                _staged, activated, _first, rollback_at = _erasure_deployment_state(conn)
                if activated is None or rollback_at is not None:
                    raise RuntimeError("tracebed erasure deployment is not active")
                _ensure_split_roles_active(conn)
                if not _erasure_role_state_is_active(conn):
                    raise RuntimeError("tracebed erasure deployment has disabled login")
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _probe_activated_split_role(migration_dsn, API_ROLE, api_password)
                _probe_activated_split_role(migration_dsn, WORKER_ROLE, worker_password)
                _require_distinct_probe_credentials(
                    migration_dsn,
                    api_probe_role=API_ROLE,
                    api_password=api_password,
                    worker_probe_role=WORKER_ROLE,
                    worker_password=worker_password,
                )
                if erasure_password:
                    _probe_activated_erasure_role(migration_dsn, erasure_password)
                    _require_erasure_cross_probes(
                        migration_dsn,
                        erasure_password=erasure_password,
                        api_password=api_password,
                    )
                return
            if not cutover_before:
                # Validate both future credentials before 0011 can create its
                # cutover receipt or change the legacy app role to NOLOGIN.
                # Validate every pre-existing protected identity before any
                # CREATE. In particular, a hostile foundation group must not
                # leave a newly created legacy application role behind.
                _validate_existing_app_role_for_latest_migration(conn)
                _validate_existing_foundation_roles(conn)
                _validate_existing_split_roles_for_latest_migration(conn)
            else:
                # Validate every non-split protected role, the authenticated
                # profile, and the receipt *before* even classifying marker-
                # null split residue. A corrupt foundation/app state must
                # preserve split verifiers and held sessions as evidence.
                state = _ensure_existing_cutover_non_split_fence(conn)
                if state.rollback_quarantined_at is not None:
                    raise RuntimeError("tracebed authority cutover is quarantined for rollback")
                if state.activated_at is not None:
                    # An active retry is intentionally a read-only authority
                    # validation plus physical own/cross credential probes.
                    # It must not run yoyo, repair a partition, clean a nonce,
                    # or append a receipt before returning.
                    publication_state = _classify_split_role_publication(conn)
                    if publication_state != "active":
                        raise RuntimeError("tracebed activated cutover has disabled split roles")
                    if _erasure_cutover_present(conn):
                        _ensure_exact_yoyo_history(conn, tip="0012_erasure_saga")
                        _ensure_latest_authority_epoch_profile(conn, expected="cutover_0012")
                        erasure_state = _erasure_cutover_activation_state(conn)
                        if erasure_state.rollback_quarantined_at is not None:
                            raise RuntimeError("tracebed erasure cutover is quarantined for rollback")
                        if erasure_state.activated_at is None:
                            raise RuntimeError(
                                "tracebed erasure cutover requires explicit cutover-0012 activation"
                            )
                    if compose_v1:
                        attest_compose_v1_hba(conn, reload=False)
                    _activate_split_roles(
                        conn,
                        owner_dsn=migration_dsn,
                        api_password=api_password,
                        worker_password=worker_password,
                        compose_v1=compose_v1,
                    )
                    return
                # Only after every non-split predicate succeeded may safe
                # marker-null residue be made inert before stale cleanup,
                # yoyo, or partition repair.
                _recover_marker_null_split_residue(conn)
            # Stale nonce cleanup is deliberately after every read-only
            # topology/identity preflight.  A valid probe is evidence too: an
            # unsafe group or source profile must leave it untouched when the
            # bootstrap refuses, rather than partially mutating the cluster.
            _cleanup_stale_credential_probes(conn)
            if not cutover_before:
                # Role DDL is cluster-global even though this connection is
                # autocommit. Keep the whole missing-role creation phase in
                # one explicit transaction so an injected/create failure
                # cannot strand a partial protected-role catalog.
                with conn.transaction():
                    _ensure_app_role_for_latest_migration(conn, app_password)
                    ensure_foundation_roles(conn)
                    _ensure_prepared_transactions_clean(conn)
                quarantine_legacy_app_for_cutover(
                    conn,
                    owner_dsn=migration_dsn,
                    app_password=app_password,
                    ingress_quarantined=ingress_quarantined,
                )
            # Initial bootstrap stops at c11. E2 is intentionally not an
            # ordinary startup migration: it needs a separately authenticated
            # close/drain/activate/open lifecycle action.
            apply_migrations(migration_dsn, through="0011_authority_cutover")
            ensure_schema_current(conn)
            if _cutover_present(conn):
                _ensure_dedicated_cluster_inventory(conn)
                _ensure_prepared_transactions_clean(conn)
                _ensure_authority_epoch_profile_current(conn)
                if compose_v1:
                    attest_compose_v1_hba(conn, reload=False)
                _activate_split_roles(
                    conn,
                    owner_dsn=migration_dsn,
                    api_password=api_password,
                    worker_password=worker_password,
                    compose_v1=compose_v1,
                )
        finally:
            if locked:
                with conn.cursor() as cursor:
                    cursor.execute(_UNLOCK_SQL, (BOOTSTRAP_LOCK_KEY,))


def main() -> int:
    """Installed ``tracebed-db-bootstrap`` command; failures are non-zero and secret-free."""
    owner_dsn = os.environ.get(_OWNER_DSN_ENV, "")
    app_password = os.environ.get(_APP_PASSWORD_ENV, "")
    api_password = os.environ.get(_API_PASSWORD_ENV, "")
    worker_password = os.environ.get(_WORKER_PASSWORD_ENV, "")
    erasure_password = os.environ.get(_ERASURE_PASSWORD_ENV, "")
    cluster_scope = os.environ.get(_CLUSTER_SCOPE_ENV, "")
    action = os.environ.get(_BOOTSTRAP_ACTION_ENV, _BOOTSTRAP_APPLY_ACTION)
    try:
        require_compose_v1_profile(os.environ)
        if LEGACY_INGRESS_ENV in os.environ:
            raise ConfigError("compose-v1 HBA profile is required")
        bootstrap_database(
            owner_dsn,
            app_password,
            api_password,
            worker_password,
            cluster_scope,
            erasure_password=erasure_password,
            ingress_quarantined=True,
            hba_profile=os.environ.get(HBA_PROFILE_ENV),
            action=action,
        )
    except Exception:
        print("tracebed-db-bootstrap failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
