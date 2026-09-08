-- The cutover receipt is monotonic: once activity exists, operators migrate
-- forward instead of resurrecting a credential/ACL boundary around live data.
SET LOCAL search_path = public, pg_catalog;
-- This pre-lock fence intentionally refuses a direct yoyo invocation before
-- it can wait on, or mutate, any cutover relation.  The ingress GUC is an
-- explicit operator assertion, not evidence PostgreSQL can derive from HBA.
DO $$
BEGIN
    IF current_setting('tracebed.atomic_migration_runner', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.ingress_quarantined', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.cluster_scope', true) IS DISTINCT FROM 'dedicated'
       OR session_user IS DISTINCT FROM current_user
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       OR (SELECT count(*) FROM pg_database) <> 4
       OR EXISTS (
           SELECT 1 FROM pg_database
            WHERE datname NOT IN (current_database(), 'postgres', 'template0', 'template1')
               OR datdba IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname = current_user)
       )
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'postgres')
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'template1')
       OR NOT EXISTS (
           SELECT 1 FROM pg_database WHERE datname = 'template0' AND datallowconn IS FALSE
       )
       OR current_setting('max_prepared_transactions')::integer <> 0
       OR EXISTS (SELECT 1 FROM pg_prepared_xacts) THEN
        RAISE EXCEPTION 'authority cutover rollback requires the Tracebed atomic runner, trusted ingress, and dedicated stop-the-world safety'
            USING ERRCODE = '55000';
    END IF;
END
$$;
DO $$
DECLARE
    role_name text;
    relation_name text;
    role_state record;
    cutover_state record;
    epoch_state record;
    child record;
    child_privileges text;
    extension_routine record;
BEGIN
    LOCK TABLE project, principal, agent_type, agent_registration, principal_grant,
               run_owner, work_queue, dead_letter, outcome_event, trace_index,
               trace_learning_job, authority_cutover_state, authority_admission_state,
               public._yoyo_migration
        IN ACCESS EXCLUSIVE MODE;
    IF current_setting('tracebed.atomic_migration_runner', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.ingress_quarantined', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.cluster_scope', true) IS DISTINCT FROM 'dedicated'
       OR (SELECT count(*) FROM pg_database) <> 4
       OR EXISTS (
           SELECT 1 FROM pg_database
            WHERE datname NOT IN (current_database(), 'postgres', 'template0', 'template1')
               OR datdba IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname = current_user)
       )
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'postgres')
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'template1')
       OR NOT EXISTS (
           SELECT 1 FROM pg_database WHERE datname = 'template0' AND datallowconn IS FALSE
       )
       OR current_setting('max_prepared_transactions')::integer <> 0
       OR EXISTS (SELECT 1 FROM pg_prepared_xacts) THEN
        RAISE EXCEPTION 'authority cutover rollback requires dedicated stop-the-world safety'
            USING ERRCODE = '55000';
    END IF;
    IF session_user IS DISTINCT FROM current_user
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'authority cutover rollback requires a direct superuser migration session'
            USING ERRCODE = '55000';
    END IF;
    -- yoyo 9's current-revision API ignores tracking rows it cannot match to
    -- packaged migrations. Authenticate the real locked table instead: every
    -- id/hash/apply receipt must be the exact known 0001..0011 chain before
    -- this migration changes a role, ACL, trigger, or receipt.
    IF EXISTS (
        WITH expected(ordinal, migration_id, migration_hash) AS (
            VALUES
                (1, '0001_registries', 'ca9fd297ce94f6dad44e14508a2d44f581a717e4387ec7ba32c38c1b67d6a2b4'),
                (2, '0002_partitioned', '22e2dc0758e77c7d1a28de420862111dc8a89da16305240bc2c7d53126e8eeb5'),
                (3, '0003_rls', '5181105981b30dbc0d9b20a8cedff308e51341d5bdd3501326468fcafd35320f'),
                (4, '0004_lifecycle', '332a0480e21dda2937e824595d1d570ccaa855848ee91a58cb47b8ecae513231'),
                (5, '0005_bm25', 'f710f686c18ac096cf1d749008c49e24ed08a36f8eb015fb3f70a5a162b90d45'),
                (6, '0006_q_update_ledger', '80d963725d38aa7e6e3618d918f9894fe52f5b9927bd1d937e0488f65e8c5551'),
                (7, '0007_project_provisioning', '3e4a20db26abaa4ebe83aa4ae2b3d20f3f412cb413db3062db54de019ab02eb1'),
                (8, '0008_trace_learning_job', '0c4d2368802cc954f4d160aa3a72b162bd36e068a8f2a663d47d2bf160e59e2f'),
                (9, '0009_trace_index_terminal_freeze', '796f7faa2c7e658d3e2948347db53a52a44ead0a97edd382ab55548a7216a722'),
                (10, '0010_authority_foundation', 'f33c0f4e096079c0c0c966b721ed8fb10389c9112766ec5398ab03611b4f319d'),
                (11, '0011_authority_cutover', '657a61cff328a14ee991d76f852d1e28af46b65fbe90f48e7338ec8caef8e271')
        ), actual AS (
            SELECT row_number() OVER (ORDER BY applied_at_utc, migration_id, migration_hash) AS ordinal,
                   migration_id, migration_hash, applied_at_utc,
                   lag(applied_at_utc) OVER (ORDER BY applied_at_utc, migration_id, migration_hash)
                       AS previous_applied_at
              FROM public._yoyo_migration
        )
        SELECT 1
          FROM expected
          FULL JOIN actual USING (ordinal)
         WHERE actual.migration_id IS DISTINCT FROM expected.migration_id
            OR actual.migration_hash IS DISTINCT FROM expected.migration_hash
            OR actual.applied_at_utc IS NULL
            OR NOT isfinite(actual.applied_at_utc)
            OR (
                actual.previous_applied_at IS NOT NULL
                AND actual.applied_at_utc <= actual.previous_applied_at
            )
    ) THEN
        RAISE EXCEPTION 'authority cutover rollback requires the exact yoyo migration history'
            USING ERRCODE = '55000';
    END IF;
    -- Authenticate every helper that will be used to validate the cutover
    -- chain before calling an assertion, set-digest, or receipt routine.
    IF EXISTS (
        SELECT 1
          FROM (VALUES
              ('public.authority_acl_frame(bytea)',
               'c7269b88c25be475938b00b221ccc0ea134dca4622e3296aa9406ae3edde25ae'),
              ('public.authority_acl_set_digest(bytea[])',
               'ef071df8440c70f411688f9eb8872fc5f6863e8922ce049c2d641925d9b52f37'),
              ('public.authority_acl_epoch_receipt(bigint,public.authority_acl_profile,integer,bytea,bytea,bytea,bytea,bytea,public.authority_yoyo_lock_repair,bytea,name,name,timestamp with time zone)',
               '1a26d306373a6b8a2b64df841207370f39293ca27d9f46cde4302c8b0a1ab66c'),
              ('public.authority_acl_profile_actual_tuples(public.authority_acl_profile)',
               'ff4b7c498b18f42c16e6a66159f909ed718d57d03e5c973efc25a82f27d3ef1e'),
              ('public.authority_acl_security_assert(public.authority_acl_profile)',
               '4a35bd197fe7c36df49288cf310cb6db3140bdcbae76e640df07d15013d38640'),
              ('public.authority_schema_profile_actual_tuples(public.authority_acl_profile)',
               '6ed189825b5d7a81db0d9dc6f9bfed6a44f85d7a2a579ddfced2a91ca7b8058d'),
              ('public.authority_schema_security_assert(public.authority_acl_profile)',
               'edc64a6dbd45a2fe6c472f87e7b56d841b47ccc36cc191351c4046b4ecca9b35')
          ) AS expected(signature, digest)
          LEFT JOIN LATERAL (
              SELECT encode(sha256(convert_to(pg_get_functiondef(to_regprocedure(expected.signature)), 'UTF8')), 'hex') AS digest
          ) AS actual ON true
         WHERE actual.digest IS DISTINCT FROM expected.digest
    ) THEN
        RAISE EXCEPTION 'authority cutover rollback refuses an unauthenticated digest helper'
            USING ERRCODE = '55000';
    END IF;
    -- Bootstrap commits this receipt-side quarantine only after the operator
    -- has closed ingress.  The rollback migration is intentionally unable to
    -- manufacture that fence: a direct yoyo invocation must fail rather than
    -- race a live credential publication or activity marker.
    SELECT cutover_at, ingress_attested_at, activated_at, first_activity_at, rollback_quarantined_at,
           legacy_dead_letter_rows, legacy_outcome_rows
      INTO cutover_state
      FROM public.authority_cutover_state
     WHERE singleton
     FOR UPDATE;
    IF NOT FOUND
       OR cutover_state.cutover_at IS NULL
       OR NOT isfinite(cutover_state.cutover_at)
       OR NOT isfinite(cutover_state.ingress_attested_at)
       OR cutover_state.ingress_attested_at IS DISTINCT FROM cutover_state.cutover_at
       OR cutover_state.activated_at IS NULL
       OR NOT isfinite(cutover_state.activated_at)
       OR cutover_state.activated_at < cutover_state.cutover_at
       OR cutover_state.rollback_quarantined_at IS NULL
       OR NOT isfinite(cutover_state.rollback_quarantined_at)
       OR cutover_state.rollback_quarantined_at < cutover_state.activated_at
       OR cutover_state.first_activity_at IS NOT NULL THEN
        RAISE EXCEPTION 'authority cutover rollback requires a committed pre-activity quarantine'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM public.authority_admission_state
         WHERE singleton AND NOT admissions_open
    ) THEN
        RAISE EXCEPTION 'authority cutover rollback requires closed admission'
            USING ERRCODE = '55000';
    END IF;
    IF (SELECT count(*) FROM dead_letter WHERE authority_version = 0)
           <> cutover_state.legacy_dead_letter_rows
       OR (SELECT count(*) FROM outcome_event WHERE authority_version = 0)
           <> cutover_state.legacy_outcome_rows
       OR EXISTS (SELECT 1 FROM dead_letter WHERE authority_version <> 0)
       OR EXISTS (SELECT 1 FROM outcome_event WHERE authority_version <> 0) THEN
        RAISE EXCEPTION 'authority cutover rollback refuses cutover history/count drift'
            USING ERRCODE = '55000';
    END IF;
    -- Direct yoyo rollback must not trust bootstrap as its only profile
    -- fence.  Prove the append-only cutover receipt is still the current
    -- catalog before changing a single role, grant, trigger, or default.
    SELECT profile, profile_version, result_acl_digest, result_schema_digest
      INTO epoch_state
      FROM public.authority_acl_epoch
     ORDER BY epoch DESC
     LIMIT 1
     FOR SHARE;
    IF NOT FOUND
       OR epoch_state.profile IS DISTINCT FROM 'cutover_0011'::public.authority_acl_profile
       OR epoch_state.profile_version <> 2
       OR epoch_state.result_acl_digest
            IS DISTINCT FROM public.authority_acl_security_assert('cutover_0011')
       OR epoch_state.result_schema_digest
            IS DISTINCT FROM public.authority_schema_security_assert('cutover_0011') THEN
        RAISE EXCEPTION 'authority cutover rollback refuses profile drift'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        WITH ordered AS (
            SELECT epoch_row.*, lag(epoch) OVER (ORDER BY epoch) AS predecessor_epoch,
                   lag(profile) OVER (ORDER BY epoch) AS predecessor_profile,
                   lag(receipt_digest) OVER (ORDER BY epoch) AS predecessor_receipt,
                   lag(result_acl_digest) OVER (ORDER BY epoch) AS predecessor_acl_digest,
                   lag(result_schema_digest) OVER (ORDER BY epoch) AS predecessor_schema_digest
              FROM public.authority_acl_epoch AS epoch_row
        ), validated AS (
            SELECT *, CASE profile
                WHEN 'genuine_0010' THEN decode(
                    '8420a2ef2badd4d5c2494ddc57c87a6e6b9460100f5bcd64a24cf18989d21668', 'hex'
                )
                WHEN 'cutover_0011' THEN decode(
                    '119d169d86072837b6ccbab013fbd3b808bf9e1da2b09daab4794597f94dbb65', 'hex'
                )
                WHEN 'hardened_0010' THEN decode(
                    'f809427341baeb07779d40801bd068597abba50910f6f8107fcdf8f9e722027c', 'hex'
                )
            END AS expected_contract
              FROM ordered
        )
        SELECT 1 FROM validated
         WHERE profile_version <> 2
            OR epoch <> COALESCE(predecessor_epoch + 1, 0)
            OR NOT (
                (predecessor_profile IS NULL AND profile = 'genuine_0010')
                OR (predecessor_profile IN ('genuine_0010', 'hardened_0010') AND profile = 'cutover_0011')
                OR (predecessor_profile = 'cutover_0011' AND profile = 'hardened_0010')
            )
            OR profile_contract_digest IS DISTINCT FROM expected_contract
            OR NOT (
                (predecessor_epoch IS NULL
                 AND source_acl_digest = result_acl_digest
                 AND source_schema_digest = result_schema_digest)
                OR (predecessor_epoch IS NOT NULL
                    AND source_acl_digest = predecessor_acl_digest
                    AND source_schema_digest = predecessor_schema_digest)
            )
            OR previous_receipt_digest
                 IS DISTINCT FROM COALESCE(predecessor_receipt, decode(repeat('00', 32), 'hex'))
            OR receipt_digest IS DISTINCT FROM public.authority_acl_epoch_receipt(
                epoch, profile, profile_version, profile_contract_digest,
                source_acl_digest, result_acl_digest, source_schema_digest, result_schema_digest,
                yoyo_lock_repair, previous_receipt_digest, actor_session_user, actor_current_user,
                transitioned_at
            )
    ) THEN
        RAISE EXCEPTION 'authority cutover rollback refuses an invalid epoch receipt chain'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
         WHERE rolname IN (
             current_user, 'tracebed_owner', 'tracebed_app', 'tracebed_api', 'tracebed_worker',
             'tracebed_erasure', 'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
         ) AND rolconfig IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM pg_db_role_setting AS setting
        JOIN pg_roles AS protected_role ON protected_role.oid = setting.setrole
        WHERE protected_role.rolname IN (
            current_user, 'tracebed_owner', 'tracebed_app', 'tracebed_api', 'tracebed_worker',
            'tracebed_erasure', 'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
        )
    ) OR EXISTS (
        SELECT 1 FROM pg_db_role_setting
         WHERE setrole = 0
           AND setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))
    ) THEN
        RAISE EXCEPTION 'authority cutover rollback refuses protected role or database settings'
            USING ERRCODE = '55000';
    END IF;
    -- A disabled legacy credential may be restored only when its verifier is
    -- still a usable SCRAM secret.  Do this before any role or ACL mutation.
    SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
           role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
           auth.rolpassword, auth.rolvaliduntil
      INTO role_state
      FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid
     WHERE role.rolname = 'tracebed_app';
    IF NOT FOUND OR role_state.rolcanlogin OR role_state.rolsuper
       OR role_state.rolcreatedb OR role_state.rolcreaterole OR role_state.rolinherit
       OR role_state.rolbypassrls OR role_state.rolreplication OR role_state.rolconnlimit <> -1
       OR role_state.rolpassword IS NULL OR role_state.rolpassword NOT LIKE 'SCRAM-SHA-256$%'
       OR role_state.rolvaliduntil IS NOT NULL
       OR EXISTS (
           SELECT 1 FROM pg_auth_members AS membership
           JOIN pg_roles AS app_role
             ON app_role.oid = membership.member OR app_role.oid = membership.roleid
            WHERE app_role.rolname = 'tracebed_app'
       ) THEN
        RAISE EXCEPTION 'authority cutover rollback refuses unsafe legacy application role'
            USING ERRCODE = '55000';
    END IF;
    FOREACH role_name IN ARRAY ARRAY[
        'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
    ] LOOP
        SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
               role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
               auth.rolpassword, auth.rolvaliduntil
          INTO role_state
          FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid
         WHERE role.rolname = role_name;
        IF NOT FOUND OR role_state.rolcanlogin OR role_state.rolsuper OR role_state.rolcreatedb
           OR role_state.rolcreaterole OR role_state.rolinherit OR role_state.rolbypassrls
           OR role_state.rolreplication OR role_state.rolconnlimit <> -1
           OR role_state.rolpassword IS NOT NULL OR role_state.rolvaliduntil IS NOT NULL THEN
            RAISE EXCEPTION 'authority cutover rollback refuses unsafe foundation group'
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
    FOREACH role_name IN ARRAY ARRAY['tracebed_api', 'tracebed_worker'] LOOP
        SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
               role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
               auth.rolpassword, auth.rolvaliduntil
          INTO role_state
          FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid
         WHERE role.rolname = role_name;
        IF NOT FOUND OR role_state.rolcanlogin OR role_state.rolsuper
           OR role_state.rolcreatedb OR role_state.rolcreaterole
           OR NOT role_state.rolinherit OR role_state.rolbypassrls OR role_state.rolreplication
           OR role_state.rolconnlimit <> -1
           OR role_state.rolpassword IS NULL OR role_state.rolpassword NOT LIKE 'SCRAM-SHA-256$%'
           OR role_state.rolvaliduntil IS NOT NULL THEN
            RAISE EXCEPTION 'authority cutover rollback refuses unsafe split role' USING ERRCODE = '55000';
        END IF;
    END LOOP;
    IF EXISTS (
        SELECT 1
          FROM pg_auth_members AS membership
          JOIN pg_roles AS granted ON granted.oid = membership.roleid
          JOIN pg_roles AS member ON member.oid = membership.member
         WHERE (granted.rolname IN (
                   'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group',
                   'tracebed_api', 'tracebed_worker'
               )
            OR member.rolname IN (
                   'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group',
                   'tracebed_api', 'tracebed_worker'
               ))
           AND NOT (
               (granted.rolname = 'tracebed_api_group' AND member.rolname = 'tracebed_api'
                AND membership.admin_option IS FALSE AND membership.inherit_option IS TRUE
                AND membership.set_option IS FALSE)
               OR
               (granted.rolname = 'tracebed_worker_group' AND member.rolname = 'tracebed_worker'
                AND membership.admin_option IS FALSE AND membership.inherit_option IS TRUE
                AND membership.set_option IS FALSE)
           )
    ) OR (SELECT count(*) FROM pg_auth_members AS membership
           JOIN pg_roles AS granted ON granted.oid = membership.roleid
           JOIN pg_roles AS member ON member.oid = membership.member
          WHERE (granted.rolname = 'tracebed_api_group' AND member.rolname = 'tracebed_api')
             OR (granted.rolname = 'tracebed_worker_group' AND member.rolname = 'tracebed_worker')) <> 2 THEN
        RAISE EXCEPTION 'authority cutover rollback refuses unexpected role membership'
            USING ERRCODE = '55000';
    END IF;
    -- ``pg_shdepend`` is not a complete ownership inventory.  Refuse every
    -- protected deployment/runtime role that owns an object or carries an ACL
    -- delegation before subtracting the narrow cutover allowlist below.
    FOREACH role_name IN ARRAY ARRAY[
        'tracebed_app', 'tracebed_api_group', 'tracebed_worker_group',
        'tracebed_erasure_group', 'tracebed_api', 'tracebed_worker'
    ] LOOP
        IF EXISTS (
            SELECT 1 FROM (
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
            JOIN pg_roles AS owner_role ON owner_role.oid = ownership.owner_oid
            WHERE owner_role.rolname = role_name
        ) THEN
            RAISE EXCEPTION 'authority cutover rollback refuses protected-role ownership'
                USING ERRCODE = '55000';
        END IF;
        IF EXISTS (
            SELECT 1 FROM (
                SELECT database.datdba AS owner_oid, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_database AS database CROSS JOIN LATERAL aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) AS privilege
                UNION ALL SELECT tablespace.spcowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_tablespace AS tablespace CROSS JOIN LATERAL aclexplode(COALESCE(tablespace.spcacl, acldefault('t', tablespace.spcowner))) AS privilege
                UNION ALL SELECT namespace.nspowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_namespace AS namespace CROSS JOIN LATERAL aclexplode(COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))) AS privilege
                UNION ALL SELECT relation.relowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_class AS relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS privilege
                UNION ALL SELECT routine.proowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_proc AS routine CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, acldefault('f', routine.proowner))) AS privilege
                UNION ALL SELECT type.typowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_type AS type CROSS JOIN LATERAL aclexplode(COALESCE(type.typacl, acldefault('T', type.typowner))) AS privilege
                UNION ALL SELECT language.lanowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_language AS language CROSS JOIN LATERAL aclexplode(COALESCE(language.lanacl, acldefault('l', language.lanowner))) AS privilege
                UNION ALL SELECT wrapper.fdwowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_foreign_data_wrapper AS wrapper CROSS JOIN LATERAL aclexplode(COALESCE(wrapper.fdwacl, acldefault('F', wrapper.fdwowner))) AS privilege
                UNION ALL SELECT server.srvowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_foreign_server AS server CROSS JOIN LATERAL aclexplode(COALESCE(server.srvacl, acldefault('S', server.srvowner))) AS privilege
                UNION ALL SELECT metadata.lomowner, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_largeobject_metadata AS metadata CROSS JOIN LATERAL aclexplode(COALESCE(metadata.lomacl, acldefault('L', metadata.lomowner))) AS privilege
                UNION ALL SELECT default_acl.defaclrole, privilege.grantee, privilege.grantor, privilege.is_grantable
                  FROM pg_default_acl AS default_acl CROSS JOIN LATERAL aclexplode(default_acl.defaclacl) AS privilege
            ) AS acl_entry
            JOIN pg_roles AS grantee_role ON grantee_role.oid = acl_entry.grantee
            WHERE grantee_role.rolname = role_name
              AND (acl_entry.is_grantable OR acl_entry.grantor IS DISTINCT FROM acl_entry.owner_oid)
        ) THEN
            RAISE EXCEPTION 'authority cutover rollback refuses protected-role grant delegation'
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM public.authority_cutover_state WHERE first_activity_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM work_queue) THEN
        RAISE EXCEPTION 'authority cutover rollback refuses activity' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_stat_activity
         WHERE pid <> pg_backend_pid()
           AND usename IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')
    ) THEN
        RAISE EXCEPTION 'authority cutover rollback requires no runtime sessions' USING ERRCODE = '55000';
    END IF;
    ALTER TABLE trace_learning_job NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE trace_learning_job DISABLE ROW LEVEL SECURITY;
    IF EXISTS (SELECT 1 FROM trace_learning_job WHERE state = 'running') THEN
        RAISE EXCEPTION 'authority cutover rollback refuses running learning leases' USING ERRCODE = '55000';
    END IF;
    ALTER TABLE trace_learning_job ENABLE ROW LEVEL SECURITY;
    ALTER TABLE trace_learning_job FORCE ROW LEVEL SECURITY;

    -- Do not normalize arbitrary ACLs with a broad REVOKE.  The exact 0011
    -- matrix is removed below; any unexpected protected-role ACL remains a
    -- shared dependency and must make the rollback fail rather than silently
    -- erasing an operator-owned grant.
    FOREACH role_name IN ARRAY ARRAY['tracebed_api', 'tracebed_worker'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            RAISE EXCEPTION 'authority cutover rollback requires split roles' USING ERRCODE = '55000';
        END IF;
    END LOOP;

    -- Subtract precisely the committed 0011 ACL matrix.  The residual shared
    -- dependency proof immediately afterward is intentionally before any
    -- DROP/ALTER, so an operator's unrelated ACL makes rollback refuse and
    -- the temporary revocations roll back with the migration transaction.
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM tracebed_api_group, tracebed_worker_group', current_database());
    REVOKE USAGE ON SCHEMA public FROM tracebed_api_group, tracebed_worker_group;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'tokenizer_catalog') THEN
        REVOKE USAGE ON SCHEMA tokenizer_catalog FROM tracebed_api_group, tracebed_worker_group;
        REVOKE SELECT (name, config) ON tokenizer_catalog.tokenizer, tokenizer_catalog.text_analyzer
            FROM tracebed_api_group, tracebed_worker_group;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'bm25_catalog') THEN
        REVOKE USAGE ON SCHEMA bm25_catalog FROM tracebed_api_group, tracebed_worker_group;
    END IF;
    REVOKE EXECUTE ON FUNCTION tokenizer_catalog.tokenize(text, text)
        FROM tracebed_api_group, tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION bm25_catalog.to_bm25query(regclass, bm25_catalog.bm25vector)
        FROM tracebed_api_group;
    REVOKE EXECUTE ON FUNCTION bm25_catalog.search_bm25query(
        bm25_catalog.bm25vector, bm25_catalog.bm25query
    ) FROM tracebed_api_group;
    REVOKE EXECUTE ON FUNCTION bm25_catalog._vchord_bm25_cast_array_to_bm25vector(
        integer[], integer, boolean
    ) FROM tracebed_api_group, tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION public.halfvec(halfvec, integer, boolean)
        FROM tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION public.cosine_distance(halfvec, halfvec)
        FROM tracebed_api_group;
    REVOKE USAGE ON TYPE public.halfvec, bm25_catalog.bm25vector, bm25_catalog.bm25query
        FROM tracebed_api_group;
    REVOKE USAGE ON TYPE public.halfvec, bm25_catalog.bm25vector FROM tracebed_worker_group;
    REVOKE SELECT ON public.project, public.principal, public.agent_type, public.agent_registration,
                     public.principal_grant, public.project_config, public.agent_type_config
        FROM tracebed_api_group, tracebed_worker_group;
    REVOKE SELECT ON public.killswitch_state FROM tracebed_api_group;
    REVOKE SELECT, INSERT, UPDATE ON public.killswitch_state FROM tracebed_worker_group;
    REVOKE SELECT ON public.embedding_model, public.scoring_epoch FROM tracebed_worker_group;
    REVOKE SELECT, INSERT ON public.work_queue FROM tracebed_api_group;
    REVOKE USAGE, SELECT ON SEQUENCE public.work_queue_id_seq FROM tracebed_api_group;
    REVOKE SELECT, UPDATE, DELETE ON public.work_queue FROM tracebed_worker_group;
    REVOKE SELECT, INSERT ON public.dead_letter FROM tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION public.subject_digests_are_valid(bytea[]) FROM tracebed_api_group, tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION public.tracebed_mark_authority_activity() FROM tracebed_api_group, tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION public.tracebed_require_active_grant(uuid, uuid, uuid, uuid, text, text)
        FROM tracebed_api_group;
    REVOKE EXECUTE ON FUNCTION public.tracebed_close_authority_admission(),
                               public.tracebed_open_authority_admission(),
                               public.tracebed_assert_authority_runtime_drained(),
                               public.tracebed_assert_authority_admission_closed()
        FROM tracebed_owner;
    REVOKE EXECUTE ON FUNCTION public.tracebed_lock_subject_bindings(uuid, text[])
        FROM tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION public.tracebed_runtime_readiness()
        FROM tracebed_api_group, tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION public.tracebed_runtime_prepublication_readiness()
        FROM tracebed_api_group, tracebed_worker_group;
    FOR child IN
        SELECT relation.relname AS parent_name, relation.relname AS leaf_name
          FROM pg_class AS relation
          JOIN pg_namespace AS relation_schema ON relation_schema.oid = relation.relnamespace
         WHERE relation_schema.nspname = 'public'
           AND relation.relname IN (
               'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
               'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
               'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job','run_owner'
           )
        UNION ALL
        SELECT parent.relname AS parent_name, leaf.relname AS leaf_name
          FROM pg_inherits AS inheritance
          JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid
          JOIN pg_class AS parent ON parent.oid = inheritance.inhparent
          JOIN pg_namespace AS leaf_schema ON leaf_schema.oid = leaf.relnamespace
          JOIN pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace
         WHERE parent_schema.nspname = 'public' AND leaf_schema.nspname = 'public'
           AND parent.relname IN (
               'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
               'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
               'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job','run_owner'
           )
    LOOP
        child_privileges := CASE child.parent_name
            WHEN 'memory_item' THEN 'SELECT' WHEN 'memory_link' THEN 'SELECT'
            WHEN 'derived_state' THEN 'SELECT' WHEN 'trace_index' THEN 'SELECT'
            WHEN 'outcome_event' THEN 'SELECT' WHEN 'injection_log' THEN 'SELECT, INSERT'
            WHEN 'retrieval_event' THEN 'SELECT, INSERT' WHEN 'invalidation_event' THEN 'SELECT, INSERT'
            WHEN 'spend_ledger' THEN 'SELECT' WHEN 'review_queue' THEN 'SELECT'
            WHEN 'run_owner' THEN 'SELECT, INSERT' ELSE NULL END;
        IF child_privileges IS NOT NULL THEN
            EXECUTE format('REVOKE %s ON public.%I FROM tracebed_api_group', child_privileges, child.leaf_name);
        END IF;
        child_privileges := CASE child.parent_name
            WHEN 'memory_item' THEN 'SELECT, INSERT, UPDATE' WHEN 'memory_link' THEN 'SELECT'
            WHEN 'derived_state' THEN 'SELECT, INSERT, DELETE' WHEN 'trace_index' THEN 'SELECT, INSERT, UPDATE'
            WHEN 'trace_subject' THEN 'SELECT, INSERT' WHEN 'subject_key' THEN 'SELECT, INSERT'
            WHEN 'outcome_event' THEN 'SELECT, INSERT' WHEN 'injection_log' THEN 'SELECT'
            WHEN 'retrieval_event' THEN 'SELECT' WHEN 'invalidation_event' THEN 'SELECT'
            WHEN 'spend_ledger' THEN 'SELECT, INSERT, UPDATE' WHEN 'review_queue' THEN 'SELECT, INSERT'
            WHEN 'memory_status_log' THEN 'SELECT, INSERT' WHEN 'memory_q_update' THEN 'SELECT, INSERT'
            WHEN 'trace_learning_job' THEN 'SELECT, INSERT, UPDATE' WHEN 'run_owner' THEN 'SELECT'
            ELSE NULL END;
        IF child_privileges IS NOT NULL THEN
            EXECUTE format('REVOKE %s ON public.%I FROM tracebed_worker_group', child_privileges, child.leaf_name);
        END IF;
    END LOOP;
    IF EXISTS (
        SELECT 1
         FROM pg_shdepend AS dependency
          JOIN pg_roles AS dependent_role ON dependent_role.oid = dependency.refobjid
        WHERE dependent_role.rolname IN (
                 'tracebed_app', 'tracebed_api', 'tracebed_worker',
                 'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
               )
           AND dependency.refclassid = 'pg_authid'::regclass
           AND dependency.deptype IN ('a', 'i', 'r', 't', 'o')
    ) THEN
        RAISE EXCEPTION 'authority cutover rollback refuses unexpected protected-role access'
            USING ERRCODE = '55000';
    END IF;

    DROP TRIGGER work_queue_authority_activity ON public.work_queue;
    DROP TRIGGER dead_letter_authority_activity ON public.dead_letter;
    DROP TRIGGER outcome_event_authority_activity ON public.outcome_event;
    DROP TRIGGER run_owner_authority_activity ON public.run_owner;
    DROP TRIGGER dead_letter_require_authority_v1_guard ON public.dead_letter;
    DROP TRIGGER outcome_event_require_authority_v1_guard ON public.outcome_event;
    DROP FUNCTION public.tracebed_mark_authority_activity_trigger();
    DROP FUNCTION public.tracebed_mark_authority_activity();
    DROP FUNCTION public.tracebed_require_active_grant(uuid, uuid, uuid, uuid, text, text);
    DROP FUNCTION public.tracebed_close_authority_admission();
    DROP FUNCTION public.tracebed_open_authority_admission();
    DROP FUNCTION public.tracebed_assert_authority_runtime_drained();
    DROP FUNCTION public.tracebed_assert_authority_admission_closed();
    DROP FUNCTION public.tracebed_lock_subject_bindings(uuid, text[]);
    DROP FUNCTION public.tracebed_runtime_readiness();
    DROP FUNCTION public.tracebed_runtime_prepublication_readiness();
    DROP FUNCTION public.dead_letter_require_authority_v1();
    DROP FUNCTION public.outcome_event_require_authority_v1();
    DROP TABLE public.authority_admission_state;

    ALTER TABLE work_queue DROP CONSTRAINT work_queue_authority_v1_only_ck;
    ALTER TABLE work_queue DROP CONSTRAINT work_queue_payload_object_ck;
    ALTER TABLE work_queue ADD CONSTRAINT work_queue_authority_v0_v1_ck CHECK (
        (authority_version = 0 AND run_id IS NULL AND source_principal_id IS NULL
         AND source_agent_type_id IS NULL AND source_grant_id IS NULL AND required_role IS NULL
         AND feedback_source IS NULL AND run_owner_principal_id IS NULL AND run_owner_agent_type_id IS NULL)
        OR (authority_version = 1 AND run_id IS NOT NULL AND source_principal_id IS NOT NULL
            AND source_agent_type_id IS NOT NULL AND source_grant_id IS NOT NULL
            AND required_role IS NOT NULL AND run_owner_principal_id IS NOT NULL
            AND run_owner_agent_type_id IS NOT NULL
            AND ((topic IN ('trace_event', 'memory_proposal') AND required_role = 'data'
                  AND feedback_source IS NULL AND source_principal_id = run_owner_principal_id
                  AND source_agent_type_id = run_owner_agent_type_id)
                 OR (topic = 'outcome_event' AND required_role = 'feedback'
                     AND feedback_source IS NOT NULL
                     AND feedback_source IN ('verdict', 'correction_adapter', 'downstream')))
        )
    );
    ALTER TABLE work_queue ALTER COLUMN authority_version SET DEFAULT 0;
    ALTER TABLE work_queue ALTER COLUMN subject_digests SET DEFAULT '{}'::bytea[];
    ALTER TABLE dead_letter ALTER COLUMN authority_version SET DEFAULT 0;
    ALTER TABLE dead_letter ALTER COLUMN subject_digests SET DEFAULT '{}'::bytea[];
    ALTER TABLE outcome_event ALTER COLUMN authority_version SET DEFAULT 0;

    -- PUBLIC hardening is intentionally not undone.  Rollback must return
    -- both split identities to the *same* staged state that 0011 accepts on a
    -- later reapply: NOLOGIN with no retained verifier.  Leaving a SCRAM
    -- verifier behind would make the forward safe-role preflight fail and
    -- turn an otherwise permitted pre-activity rollback into a dead end.
    ALTER ROLE tracebed_api NOLOGIN PASSWORD NULL;
    ALTER ROLE tracebed_worker NOLOGIN PASSWORD NULL;
    REVOKE tracebed_api_group FROM tracebed_api;
    REVOKE tracebed_worker_group FROM tracebed_worker;
    FOREACH role_name IN ARRAY ARRAY['tracebed_api', 'tracebed_worker'] LOOP
        SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
               role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
               auth.rolpassword, auth.rolvaliduntil
          INTO role_state
          FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid
         WHERE role.rolname = role_name;
        IF NOT FOUND OR role_state.rolcanlogin OR role_state.rolsuper
           OR role_state.rolcreatedb OR role_state.rolcreaterole OR NOT role_state.rolinherit
           OR role_state.rolbypassrls OR role_state.rolreplication OR role_state.rolconnlimit <> -1
           OR role_state.rolpassword IS NOT NULL OR role_state.rolvaliduntil IS NOT NULL
           OR EXISTS (
               SELECT 1 FROM pg_roles AS setting_role
                WHERE setting_role.rolname = role_name AND setting_role.rolconfig IS NOT NULL
           ) OR EXISTS (
               SELECT 1 FROM pg_db_role_setting AS setting
               JOIN pg_roles AS setting_role ON setting_role.oid = setting.setrole
                WHERE setting_role.rolname = role_name
           ) OR EXISTS (
               SELECT 1 FROM pg_auth_members AS membership
               JOIN pg_roles AS member_role ON member_role.oid = membership.member
               JOIN pg_roles AS granted_role ON granted_role.oid = membership.roleid
                WHERE member_role.rolname = role_name OR granted_role.rolname = role_name
           ) THEN
            RAISE EXCEPTION 'authority cutover rollback failed to restore staged split role'
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO tracebed_app, tracebed_api_group, tracebed_worker_group, tracebed_erasure_group', current_database());
    GRANT USAGE ON SCHEMA public TO tracebed_app, tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'tokenizer_catalog') THEN
        REVOKE USAGE, CREATE ON SCHEMA tokenizer_catalog
            FROM tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
        GRANT USAGE ON SCHEMA tokenizer_catalog TO tracebed_app;
        GRANT SELECT ON tokenizer_catalog.tokenizer, tokenizer_catalog.text_analyzer,
                        tokenizer_catalog.model, tokenizer_catalog.stopwords,
                        tokenizer_catalog.synonym
            TO tracebed_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'bm25_catalog') THEN
        REVOKE USAGE, CREATE ON SCHEMA bm25_catalog
            FROM tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
        GRANT USAGE ON SCHEMA bm25_catalog TO tracebed_app;
    END IF;
    -- Rebuild the *enumerated* 0010 legacy application matrix.  Do not use
    -- GRANT ... ON ALL TABLES: that would include yoyo bookkeeping and also
    -- undo the explicit 0008/0009 DELETE removals and 0010 authority-table
    -- restrictions.
    FOREACH relation_name IN ARRAY ARRAY[
        'project','principal','agent_type','agent_registration','embedding_model','scoring_epoch',
        'project_config','agent_type_config','killswitch_state','work_queue','dead_letter',
        'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
        'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
        'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job'
    ] LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO tracebed_app', relation_name);
    END LOOP;
    GRANT USAGE, SELECT ON SEQUENCE public.work_queue_id_seq, public.scoring_epoch_epoch_id_seq
        TO tracebed_app;
    -- The hardened rollback profile deliberately has no future-object
    -- default grants.  Reinstating 0003's broad defaults here would grant a
    -- later owner-created relation/sequence to the disabled legacy role
    -- without an authenticated profile transition.
    REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
        ON public.principal_grant FROM tracebed_app;
    GRANT SELECT ON public.principal_grant TO tracebed_app;
    REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
        ON public.run_owner FROM tracebed_app;
    GRANT SELECT, INSERT ON public.run_owner TO tracebed_app;
    REVOKE DELETE ON public.trace_index, public.trace_learning_job FROM tracebed_app;
    GRANT SELECT ON project, principal, agent_type, agent_registration, principal_grant
        TO tracebed_api_group, tracebed_worker_group;
    GRANT SELECT, INSERT ON work_queue TO tracebed_api_group;
    GRANT USAGE, SELECT ON SEQUENCE work_queue_id_seq TO tracebed_api_group;
    GRANT SELECT, UPDATE, DELETE ON work_queue TO tracebed_worker_group;
    GRANT SELECT, INSERT ON dead_letter TO tracebed_worker_group;
    GRANT SELECT, INSERT ON run_owner TO tracebed_app, tracebed_api_group;
    GRANT SELECT ON run_owner TO tracebed_worker_group;
    GRANT SELECT ON principal_grant TO tracebed_app, tracebed_api_group, tracebed_worker_group;
    GRANT EXECUTE ON FUNCTION subject_digests_are_valid(bytea[])
        TO tracebed_app, tracebed_api_group, tracebed_worker_group;
    GRANT EXECUTE ON FUNCTION tokenizer_catalog.tokenize(text, text) TO tracebed_app;
    GRANT EXECUTE ON FUNCTION bm25_catalog.to_bm25query(regclass, bm25_catalog.bm25vector)
        TO tracebed_app;
    GRANT EXECUTE ON FUNCTION bm25_catalog.search_bm25query(
        bm25_catalog.bm25vector, bm25_catalog.bm25query
    ) TO tracebed_app;
    GRANT EXECUTE ON FUNCTION bm25_catalog._vchord_bm25_cast_array_to_bm25vector(
        integer[], integer, boolean
    ) TO tracebed_app;
    GRANT EXECUTE ON FUNCTION public.halfvec(halfvec, integer, boolean) TO tracebed_app;
    GRANT EXECUTE ON FUNCTION public.cosine_distance(halfvec, halfvec) TO tracebed_app;
    GRANT USAGE ON TYPE public.halfvec, bm25_catalog.bm25vector, bm25_catalog.bm25query
        TO tracebed_app;
    -- A rollback never republishes the legacy credential.  The external
    -- ingress fence remains in force and any recovery that intentionally
    -- re-enables the historical identity is an explicit operator action
    -- after the hardened receipt has been verified.
    ALTER ROLE tracebed_app NOLOGIN;

    -- Remove only the cutover child grants, then put the pre-cutover app
    -- grants back on each of the 17 known partition families.  Namespace and
    -- parent filtering prevent an attacker-controlled homonym from changing
    -- rollback privileges.
    FOR child IN
        SELECT parent.relname AS parent_name, leaf.relname AS leaf_name
          FROM pg_inherits AS inheritance
          JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid
          JOIN pg_class AS parent ON parent.oid = inheritance.inhparent
          JOIN pg_namespace AS leaf_schema ON leaf_schema.oid = leaf.relnamespace
          JOIN pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace
         WHERE parent_schema.nspname = 'public' AND leaf_schema.nspname = 'public'
           AND parent.relname IN (
               'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
               'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
               'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job','run_owner'
           )
    LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO tracebed_app', child.leaf_name);
        IF child.parent_name = 'run_owner' THEN
            EXECUTE format(
                'REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER '
                || 'ON public.%I FROM tracebed_app',
                child.leaf_name
            );
            EXECUTE format('REVOKE SELECT, INSERT ON public.%I FROM tracebed_api_group', child.leaf_name);
            EXECUTE format('REVOKE SELECT ON public.%I FROM tracebed_worker_group', child.leaf_name);
            -- This is the exact 0010 run-owner leaf surface.  Parent grants
            -- are not a substitute here: existing leaves retain their own
            -- ACL, so omittting these direct grants would produce a
            -- hardened profile different from a genuine 0010 provisioned
            -- project.
            EXECUTE format(
                'GRANT SELECT, INSERT ON public.%I TO tracebed_app, tracebed_api_group',
                child.leaf_name
            );
            EXECUTE format('GRANT SELECT ON public.%I TO tracebed_worker_group', child.leaf_name);
        ELSIF child.parent_name IN ('trace_index', 'trace_learning_job') THEN
            EXECUTE format('REVOKE DELETE ON public.%I FROM tracebed_app', child.leaf_name);
            child_privileges := 'SELECT, INSERT, UPDATE';
        ELSE
            child_privileges := 'SELECT, INSERT, UPDATE, DELETE';
        END IF;
        IF child.parent_name <> 'run_owner' THEN
            EXECUTE format('GRANT %s ON public.%I TO tracebed_app', child_privileges, child.leaf_name);
        END IF;
    END LOOP;

    -- The cutover state is deliberately the final removed authority object:
    -- all role, ACL, queue, lease, trigger, and version reconstruction has
    -- completed before its receipt is erased.  The hardened profile below
    -- then authenticates the state without this table.
    DROP TABLE public.authority_cutover_state;

    -- hardened_0010's expected tuple set is part of 0010's checked-in
    -- immutable canonical contract.  Do not bless this rollback catalog.

    -- This follows the complete rollback reconstruction, so the resulting
    -- receipt describes the hardened-0010 state rather than an intermediate
    -- schema with cutover guards still installed.
    INSERT INTO public.authority_acl_epoch (
        epoch, profile, profile_version, source_acl_digest, result_acl_digest,
        source_schema_digest, result_schema_digest, yoyo_lock_repair
    )
    VALUES (
        (SELECT COALESCE(max(epoch), -1) + 1 FROM public.authority_acl_epoch),
        'hardened_0010',
        2,
        (SELECT result_acl_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
        public.authority_acl_security_assert('hardened_0010'),
        (SELECT result_schema_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
        public.authority_schema_security_assert('hardened_0010'),
        'not_required'
    );
END
$$;
