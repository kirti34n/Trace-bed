-- depends: 0010_authority_foundation

-- 0011 is deliberately all-or-nothing.  It stages split identities and the
-- durable authority receipt, but bootstrap alone performs the later LOGIN
-- activation after this transaction has committed.

-- This GUC is an explicit operator attestation that external ingress (HBA,
-- firewall, service routing, and every runtime client) was fenced before the
-- authority transition. SQL cannot prove those external controls; it merely
-- refuses a direct yoyo invocation that lacks the recorded assertion. Keep
-- this preflight before session DDL or relation locks.
DO $$
BEGIN
    -- This is a repository-runner invocation receipt, not a claim that a
    -- database owner cannot set an arbitrary custom GUC. It makes the raw
    -- upstream mutating yoyo CLI fail closed instead of bypassing Tracebed's
    -- one-connection atomic SQL/log/mark transaction.
    IF current_setting('tracebed.atomic_migration_runner', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'authority cutover requires the Tracebed atomic migration runner'
            USING ERRCODE = '55000';
    END IF;
    IF current_setting('tracebed.ingress_quarantined', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'authority cutover requires an external ingress quarantine attestation'
            USING ERRCODE = '55000';
    END IF;
    IF current_setting('tracebed.cluster_scope', true) IS DISTINCT FROM 'dedicated' THEN
        RAISE EXCEPTION 'authority cutover requires a dedicated PostgreSQL cluster attestation'
            USING ERRCODE = '55000';
    END IF;
    IF session_user IS DISTINCT FROM current_user
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'authority cutover requires a direct superuser migration session'
            USING ERRCODE = '55000';
    END IF;
    IF (SELECT count(*) FROM pg_database) <> 4
       OR EXISTS (
           SELECT 1 FROM pg_database
            WHERE datname NOT IN (current_database(), 'postgres', 'template0', 'template1')
       )
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = current_database())
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'postgres')
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'template1')
       OR NOT EXISTS (
           SELECT 1 FROM pg_database WHERE datname = 'template0' AND datallowconn IS FALSE
       ) THEN
        RAISE EXCEPTION 'authority cutover requires the dedicated four-database cluster inventory'
            USING ERRCODE = '55000';
    END IF;
    IF current_setting('max_prepared_transactions')::integer <> 0
       OR EXISTS (SELECT 1 FROM pg_prepared_xacts) THEN
        RAISE EXCEPTION 'authority cutover requires no prepared transactions'
            USING ERRCODE = '55000';
    END IF;
END
$$;

-- Keep remaining legacy unqualified DDL in the application schema even for
-- the dedicated superuser migration connection.  Security-definer helpers
-- set a stricter path on the function itself.
SET LOCAL search_path = public, pg_catalog;

LOCK TABLE project, principal, agent_type, agent_registration, principal_grant,
           run_owner, work_queue, dead_letter, outcome_event, trace_index,
           trace_learning_job
    IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    role_name text;
    relation_name text;
    role_state record;
    previous_acl_profile public.authority_acl_profile;
    previous_acl_digest bytea;
    previous_schema_digest bytea;
BEGIN
    IF current_setting('tracebed.atomic_migration_runner', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'authority cutover requires the Tracebed atomic migration runner'
            USING ERRCODE = '55000';
    END IF;
    IF current_setting('tracebed.ingress_quarantined', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'authority cutover requires an external ingress quarantine attestation'
            USING ERRCODE = '55000';
    END IF;
    IF current_setting('tracebed.cluster_scope', true) IS DISTINCT FROM 'dedicated' THEN
        RAISE EXCEPTION 'authority cutover requires a dedicated PostgreSQL cluster attestation'
            USING ERRCODE = '55000';
    END IF;
    IF session_user IS DISTINCT FROM current_user
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'authority cutover requires a direct superuser migration session'
            USING ERRCODE = '55000';
    END IF;
    IF current_setting('max_prepared_transactions')::integer <> 0
       OR EXISTS (SELECT 1 FROM pg_prepared_xacts) THEN
        RAISE EXCEPTION 'authority cutover requires no prepared transactions'
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
        RAISE EXCEPTION 'authority cutover refuses protected role or database settings'
            USING ERRCODE = '55000';
    END IF;
    IF (SELECT count(*) FROM pg_database) <> 4
       OR EXISTS (
           SELECT 1 FROM pg_database
            WHERE datname NOT IN (current_database(), 'postgres', 'template0', 'template1')
       )
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = current_database())
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'postgres')
       OR NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'template1')
       OR NOT EXISTS (
           SELECT 1 FROM pg_database WHERE datname = 'template0' AND datallowconn IS FALSE
       ) THEN
        RAISE EXCEPTION 'authority cutover requires the dedicated four-database cluster inventory'
            USING ERRCODE = '55000';
    END IF;
    IF (SELECT count(*) FROM pg_extension) <> 4
       OR EXISTS (
           SELECT 1
             FROM (VALUES
                ('plpgsql', '1.0', 'pg_catalog'),
                 ('vector', '0.8.2', 'public'),
                 ('pg_tokenizer', '0.1.1', 'tokenizer_catalog'),
                 ('vchord_bm25', '0.3.0', 'bm25_catalog')
             ) AS expected(extname, extversion, nspname)
             LEFT JOIN pg_extension AS extension
               ON extension.extname = expected.extname
             LEFT JOIN pg_namespace AS namespace ON namespace.oid = extension.extnamespace
            WHERE extension.extversion IS DISTINCT FROM expected.extversion
               OR namespace.nspname IS DISTINCT FROM expected.nspname
       ) THEN
        RAISE EXCEPTION 'authority cutover requires the pinned extension catalog'
            USING ERRCODE = '55000';
    END IF;
    -- The complete digest chain is a security primitive, not a mutable
    -- migration convenience.  Authenticate every helper before relying on
    -- a profile root; hashing only the outer schema assertion leaves a
    -- redefined framing/tuple helper able to mint a false receipt.
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
        RAISE EXCEPTION 'authority cutover refuses an unauthenticated digest helper'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM work_queue) THEN
        RAISE EXCEPTION 'authority cutover requires an empty work queue' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_stat_activity
         WHERE pid <> pg_backend_pid()
           AND usename IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')
    ) THEN
        RAISE EXCEPTION 'authority cutover requires no runtime sessions' USING ERRCODE = '55000';
    END IF;
    ALTER TABLE trace_learning_job NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE trace_learning_job DISABLE ROW LEVEL SECURITY;
    IF EXISTS (SELECT 1 FROM trace_learning_job WHERE state = 'running') THEN
        RAISE EXCEPTION 'authority cutover requires no running trace learning lease' USING ERRCODE = '55000';
    END IF;
    ALTER TABLE trace_learning_job ENABLE ROW LEVEL SECURITY;
    ALTER TABLE trace_learning_job FORCE ROW LEVEL SECURITY;
    IF EXISTS (
        SELECT 1 FROM project AS project
         WHERE project.status = 'active' AND project.deleted_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM principal_grant AS grant_row
               JOIN principal ON principal.principal_id = grant_row.principal_id
               JOIN agent_registration AS registration
                 ON registration.principal_id = grant_row.principal_id
                AND registration.project_id = grant_row.project_id
               WHERE grant_row.project_id = project.project_id
                 AND grant_row.role = 'admin' AND grant_row.revoked_at IS NULL
                 AND principal.revoked_at IS NULL AND registration.revoked_at IS NULL
           )
    ) THEN
        RAISE EXCEPTION 'authority cutover requires active-project admin grants' USING ERRCODE = '55000';
    END IF;
    SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole, role.rolinherit,
           role.rolbypassrls, role.rolreplication, role.rolconnlimit,
           auth.rolpassword, auth.rolvaliduntil
      INTO role_state
      FROM pg_roles AS role
      JOIN pg_authid AS auth ON auth.oid = role.oid
     WHERE role.rolname = 'tracebed_app';
    -- A prior ingress-controlled quarantine must already have committed the
    -- legacy identity to NOLOGIN.  Altering it only inside this transaction
    -- would leave a post-check connection race: an existing application
    -- client could authenticate before the transaction commits and survive
    -- the authority rewrite.  Direct yoyo therefore has no implicit
    -- quarantine bypass.
    IF NOT FOUND OR role_state.rolcanlogin OR role_state.rolsuper
       OR role_state.rolcreatedb OR role_state.rolcreaterole OR role_state.rolinherit
       OR role_state.rolbypassrls OR role_state.rolreplication
       OR role_state.rolconnlimit <> -1
       OR role_state.rolpassword IS NULL OR role_state.rolpassword NOT LIKE 'SCRAM-SHA-256$%'
       OR role_state.rolvaliduntil IS NOT NULL
       OR EXISTS (
           SELECT 1 FROM pg_auth_members AS membership
           JOIN pg_roles AS app_role
             ON app_role.oid = membership.member OR app_role.oid = membership.roleid
            WHERE app_role.rolname = 'tracebed_app'
       ) THEN
        RAISE EXCEPTION 'authority cutover refuses unsafe legacy application role'
            USING ERRCODE = '55000';
    END IF;
    FOREACH role_name IN ARRAY ARRAY[
        'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
    ] LOOP
        SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
               role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
               auth.rolpassword, auth.rolvaliduntil
          INTO role_state
          FROM pg_roles AS role
          JOIN pg_authid AS auth ON auth.oid = role.oid
         WHERE role.rolname = role_name;
        IF NOT FOUND OR role_state.rolcanlogin OR role_state.rolsuper
           OR role_state.rolcreatedb OR role_state.rolcreaterole
           OR role_state.rolinherit OR role_state.rolbypassrls
           OR role_state.rolreplication OR role_state.rolconnlimit <> -1
           OR role_state.rolpassword IS NOT NULL OR role_state.rolvaliduntil IS NOT NULL
           OR EXISTS (
               SELECT 1 FROM pg_auth_members AS membership
               JOIN pg_roles AS group_role
                 ON group_role.oid = membership.member OR group_role.oid = membership.roleid
                WHERE group_role.rolname = role_name
           ) THEN
            RAISE EXCEPTION 'authority cutover refuses unsafe foundation group' USING ERRCODE = '55000';
        END IF;
    END LOOP;
    FOREACH role_name IN ARRAY ARRAY['tracebed_api', 'tracebed_worker'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
                   role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
                   auth.rolpassword, auth.rolvaliduntil
              INTO role_state
              FROM pg_roles AS role
              JOIN pg_authid AS auth ON auth.oid = role.oid
             WHERE role.rolname = role_name;
            IF role_state.rolcanlogin OR role_state.rolsuper OR role_state.rolcreatedb
               OR role_state.rolcreaterole OR NOT role_state.rolinherit
               OR role_state.rolbypassrls OR role_state.rolreplication
               OR role_state.rolconnlimit <> -1
               OR role_state.rolpassword IS NOT NULL OR role_state.rolvaliduntil IS NOT NULL
               OR EXISTS (
                   SELECT 1 FROM pg_auth_members AS membership
                   JOIN pg_roles AS split_role
                     ON split_role.oid = membership.member OR split_role.oid = membership.roleid
                    WHERE split_role.rolname = role_name
               ) THEN
                RAISE EXCEPTION 'authority cutover refuses unsafe split role' USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_shdepend AS dependency
                JOIN pg_roles AS split_role ON split_role.oid = dependency.refobjid
                WHERE split_role.rolname = role_name
                  AND dependency.refclassid = 'pg_authid'::regclass
                  AND dependency.deptype IN ('a', 'i', 'r', 't', 'o')
            ) THEN
                RAISE EXCEPTION 'authority cutover refuses split role with ownership or access dependencies'
                    USING ERRCODE = '55000';
            END IF;
        END IF;
    END LOOP;

    -- ``pg_shdepend`` alone is not a complete ownership inventory.  Check
    -- every owner catalogue and delegable ACL shape before subtracting the
    -- 0010 allowlist below.  The migration owner is deliberately excluded:
    -- it owns this deployment's schema by design; all authority/runtime roles
    -- must remain ownership- and delegation-free.
    FOREACH role_name IN ARRAY ARRAY[
        'tracebed_app', 'tracebed_api_group', 'tracebed_worker_group',
        'tracebed_erasure_group', 'tracebed_api', 'tracebed_worker'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            CONTINUE;
        END IF;
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
            RAISE EXCEPTION 'authority cutover refuses protected-role ownership'
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
            RAISE EXCEPTION 'authority cutover refuses protected-role grant delegation'
                USING ERRCODE = '55000';
        END IF;
    END LOOP;

    -- Bind the pre-cutover catalog to the last authenticated 0010 receipt
    -- before any temporary allowlist subtraction below.  A mismatch is an
    -- operator-visible drift, never something a broad REVOKE may launder.
    SELECT profile, result_acl_digest, result_schema_digest
      INTO previous_acl_profile, previous_acl_digest, previous_schema_digest
      FROM public.authority_acl_epoch
     ORDER BY epoch DESC LIMIT 1;
    IF previous_acl_profile NOT IN ('genuine_0010', 'hardened_0010')
       OR public.authority_acl_security_assert(previous_acl_profile) IS DISTINCT FROM previous_acl_digest
       OR public.authority_schema_security_assert(previous_acl_profile) IS DISTINCT FROM previous_schema_digest THEN
        RAISE EXCEPTION 'authority cutover refuses authority profile drift'
            USING ERRCODE = '55000';
    END IF;

    -- The legacy application identity is about to lose its broad pre-0011
    -- privileges.  Subtract only the documented 0003/0005/0010 allowlist
    -- first, then require no remaining ACL dependency.  This prevents the
    -- later cutover REVOKEs from laundering an owner-granted privilege on an
    -- unrelated object or database.
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM tracebed_app', current_database());
    REVOKE USAGE ON SCHEMA public FROM tracebed_app;
    FOREACH relation_name IN ARRAY ARRAY[
        'project','principal','agent_type','agent_registration','embedding_model','scoring_epoch',
        'project_config','agent_type_config','killswitch_state','work_queue','dead_letter',
        'memory_item','memory_link','derived_state',
        'trace_subject','subject_key','outcome_event','injection_log','retrieval_event',
        'blackboard_entry','invalidation_event','spend_ledger','review_queue','memory_status_log',
        'memory_q_update'
    ] LOOP
        IF to_regclass(format('public.%I', relation_name)) IS NOT NULL THEN
            EXECUTE format('REVOKE SELECT, INSERT, UPDATE, DELETE ON public.%I FROM tracebed_app', relation_name);
        END IF;
    END LOOP;
    IF to_regclass('public._yoyo_lock') IS NOT NULL THEN
        RAISE EXCEPTION 'authority cutover refuses unexpected underscored yoyo lock relation'
            USING ERRCODE = '55000';
    END IF;
    SELECT profile, result_acl_digest, result_schema_digest
      INTO previous_acl_profile, previous_acl_digest, previous_schema_digest
      FROM public.authority_acl_epoch
     ORDER BY epoch DESC LIMIT 1;
    IF previous_acl_profile NOT IN ('genuine_0010', 'hardened_0010') THEN
        RAISE EXCEPTION 'authority cutover refuses an invalid ACL receipt predecessor'
            USING ERRCODE = '55000';
    END IF;
    IF to_regclass('public.yoyo_lock') IS NOT NULL THEN
        IF NOT (
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
               AND (
                   SELECT array_agg(privilege.privilege_type ORDER BY privilege.privilege_type)
                     FROM aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS privilege
                     JOIN pg_roles AS grantee ON grantee.oid = privilege.grantee
                    WHERE grantee.rolname = 'tracebed_app'
               ) IS NOT DISTINCT FROM CASE previous_acl_profile
                       WHEN 'genuine_0010' THEN ARRAY['DELETE', 'INSERT', 'SELECT', 'UPDATE']
                       ELSE NULL
                   END
              FROM pg_class AS relation
             WHERE relation.oid = 'public.yoyo_lock'::regclass
        ) THEN
            RAISE EXCEPTION 'authority cutover refuses unexpected yoyo lock relation'
                USING ERRCODE = '55000';
        END IF;
        IF previous_acl_profile = 'genuine_0010' THEN
            REVOKE SELECT, INSERT, UPDATE, DELETE ON public.yoyo_lock FROM tracebed_app;
        END IF;
    END IF;
    -- These parents deliberately deviate from 0003's blanket DML.  Revoke
    -- only their real 0010 surfaces: a planted UPDATE/DELETE must remain as
    -- evidence and make the residual dependency proof refuse cutover.
    REVOKE SELECT ON public.principal_grant FROM tracebed_app;
    REVOKE SELECT, INSERT ON public.run_owner FROM tracebed_app;
    REVOKE SELECT, INSERT, UPDATE ON public.trace_index, public.trace_learning_job FROM tracebed_app;
    FOR role_state IN
        SELECT leaf.relname AS relation_name, parent.relname AS parent_name
          FROM pg_inherits AS inheritance
          JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid
          JOIN pg_class AS parent ON parent.oid = inheritance.inhparent
          JOIN pg_namespace AS leaf_schema ON leaf_schema.oid = leaf.relnamespace
          JOIN pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace
         WHERE leaf_schema.nspname = 'public' AND parent_schema.nspname = 'public'
           AND parent.relname IN (
               'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
               'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
               'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job','run_owner'
           )
    LOOP
        IF role_state.parent_name = 'run_owner' THEN
            EXECUTE format('REVOKE SELECT, INSERT ON public.%I FROM tracebed_app', role_state.relation_name);
        ELSIF role_state.parent_name IN ('trace_index', 'trace_learning_job') THEN
            EXECUTE format('REVOKE SELECT, INSERT, UPDATE ON public.%I FROM tracebed_app', role_state.relation_name);
        ELSE
            EXECUTE format('REVOKE SELECT, INSERT, UPDATE, DELETE ON public.%I FROM tracebed_app', role_state.relation_name);
        END IF;
    END LOOP;
    REVOKE USAGE, SELECT ON SEQUENCE public.work_queue_id_seq, public.scoring_epoch_epoch_id_seq FROM tracebed_app;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'tokenizer_catalog') THEN
        REVOKE USAGE ON SCHEMA tokenizer_catalog FROM tracebed_app;
        -- 0005 grants the legacy app SELECT on these five fixed catalog
        -- tables.  Enumerate them rather than using ``ALL TABLES`` so a
        -- future or attacker-created tokenizer table remains cutover evidence.
        REVOKE SELECT ON tokenizer_catalog.tokenizer, tokenizer_catalog.text_analyzer,
                         tokenizer_catalog.model, tokenizer_catalog.stopwords,
                         tokenizer_catalog.synonym
            FROM tracebed_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'bm25_catalog') THEN
        REVOKE USAGE ON SCHEMA bm25_catalog FROM tracebed_app;
    END IF;
    -- A permitted 0011 rollback restores the legacy app's minimal extension
    -- surface directly (PUBLIC remains hardened).  Subtract that exact
    -- surface here too, or a rollback -> reapply would falsely look like an
    -- operator-injected ACL dependency.
    REVOKE EXECUTE ON FUNCTION tokenizer_catalog.tokenize(text, text) FROM tracebed_app;
    REVOKE EXECUTE ON FUNCTION bm25_catalog.to_bm25query(regclass, bm25_catalog.bm25vector)
        FROM tracebed_app;
    REVOKE EXECUTE ON FUNCTION bm25_catalog.search_bm25query(
        bm25_catalog.bm25vector, bm25_catalog.bm25query
    ) FROM tracebed_app;
    REVOKE EXECUTE ON FUNCTION bm25_catalog._vchord_bm25_cast_array_to_bm25vector(
        integer[], integer, boolean
    ) FROM tracebed_app;
    REVOKE EXECUTE ON FUNCTION public.halfvec(halfvec, integer, boolean) FROM tracebed_app;
    REVOKE EXECUTE ON FUNCTION public.cosine_distance(halfvec, halfvec) FROM tracebed_app;
    REVOKE USAGE ON TYPE public.halfvec, bm25_catalog.bm25vector, bm25_catalog.bm25query
        FROM tracebed_app;
    REVOKE EXECUTE ON FUNCTION public.subject_digests_are_valid(bytea[]) FROM tracebed_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM tracebed_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        REVOKE USAGE, SELECT ON SEQUENCES FROM tracebed_app;
    IF EXISTS (
        SELECT 1 FROM pg_shdepend AS dependency
        JOIN pg_roles AS app_role ON app_role.oid = dependency.refobjid
        WHERE app_role.rolname = 'tracebed_app'
          AND dependency.refclassid = 'pg_authid'::regclass
          AND dependency.deptype IN ('a', 'i', 'r', 't', 'o')
    ) THEN
        RAISE EXCEPTION 'authority cutover refuses unexpected legacy application access'
            USING ERRCODE = '55000';
    END IF;

    -- 0010 leaves a deliberately tiny group ACL matrix.  Subtract only that
    -- known matrix inside this transaction, then reject every residual shared
    -- dependency.  If any check fails, yoyo rolls these temporary REVOKEs back;
    -- no hostile grant is silently normalised before the cutover sees it.
    FOREACH role_name IN ARRAY ARRAY[
        'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
    ] LOOP
        IF EXISTS (
            SELECT 1 FROM pg_shdepend AS dependency
            JOIN pg_roles AS group_role ON group_role.oid = dependency.refobjid
            WHERE group_role.rolname = role_name
              AND dependency.refclassid = 'pg_authid'::regclass
              AND dependency.deptype = 'o'
        ) OR EXISTS (
            SELECT 1 FROM pg_default_acl AS default_acl
            JOIN pg_roles AS group_role ON group_role.oid = default_acl.defaclrole
            WHERE group_role.rolname = role_name
        ) THEN
            RAISE EXCEPTION 'authority cutover refuses foundation-group ownership'
                USING ERRCODE = '55000';
        END IF;
        EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %I', current_database(), role_name);
        EXECUTE format('REVOKE USAGE ON SCHEMA public FROM %I', role_name);
        IF role_name = 'tracebed_api_group' THEN
            REVOKE SELECT ON project, principal, agent_type, agent_registration, principal_grant FROM tracebed_api_group;
            REVOKE SELECT, INSERT ON run_owner, work_queue FROM tracebed_api_group;
            REVOKE USAGE, SELECT ON SEQUENCE work_queue_id_seq FROM tracebed_api_group;
            REVOKE EXECUTE ON FUNCTION subject_digests_are_valid(bytea[]) FROM tracebed_api_group;
        ELSIF role_name = 'tracebed_worker_group' THEN
            REVOKE SELECT ON project, principal, agent_type, agent_registration, principal_grant, run_owner FROM tracebed_worker_group;
            REVOKE SELECT, UPDATE, DELETE ON work_queue FROM tracebed_worker_group;
            REVOKE SELECT, INSERT ON dead_letter FROM tracebed_worker_group;
            REVOKE EXECUTE ON FUNCTION subject_digests_are_valid(bytea[]) FROM tracebed_worker_group;
        END IF;
        FOR role_state IN
            SELECT child.relname AS child_name, parent.relname AS parent_name
            FROM pg_inherits AS inheritance
            JOIN pg_class AS child ON child.oid = inheritance.inhrelid
            JOIN pg_class AS parent ON parent.oid = inheritance.inhparent
            JOIN pg_namespace AS child_schema ON child_schema.oid = child.relnamespace
            JOIN pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace
            WHERE parent.relname = 'run_owner'
              AND child_schema.nspname = 'public' AND parent_schema.nspname = 'public'
        LOOP
            IF role_name = 'tracebed_api_group' THEN
                EXECUTE format('REVOKE SELECT, INSERT ON public.%I FROM tracebed_api_group', role_state.child_name);
            ELSIF role_name = 'tracebed_worker_group' THEN
                EXECUTE format('REVOKE SELECT ON public.%I FROM tracebed_worker_group', role_state.child_name);
            END IF;
        END LOOP;
        IF EXISTS (
            SELECT 1 FROM pg_shdepend AS dependency
            JOIN pg_roles AS group_role ON group_role.oid = dependency.refobjid
            WHERE group_role.rolname = role_name
              AND dependency.refclassid = 'pg_authid'::regclass
              AND dependency.deptype IN ('a', 'i', 'r', 't', 'o')
        ) THEN
            RAISE EXCEPTION 'authority cutover refuses foundation group with unexpected access dependencies'
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tracebed_api') THEN
        CREATE ROLE tracebed_api NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1;
        ALTER ROLE tracebed_api RESET ALL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tracebed_worker') THEN
        CREATE ROLE tracebed_worker NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOBYPASSRLS NOREPLICATION CONNECTION LIMIT -1;
        ALTER ROLE tracebed_worker RESET ALL;
    END IF;
END
$$;

GRANT tracebed_api_group TO tracebed_api WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT tracebed_worker_group TO tracebed_worker WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
ALTER ROLE tracebed_app NOLOGIN;

CREATE TABLE public.authority_cutover_state (
    singleton boolean PRIMARY KEY CHECK (singleton),
    cutover_at timestamptz NOT NULL,
    ingress_attested_at timestamptz NOT NULL,
    activated_at timestamptz,
    first_activity_at timestamptz,
    rollback_quarantined_at timestamptz,
    legacy_dead_letter_rows bigint NOT NULL CHECK (legacy_dead_letter_rows >= 0),
    legacy_outcome_rows bigint NOT NULL CHECK (legacy_outcome_rows >= 0),
    CHECK (
        isfinite(cutover_at)
        AND isfinite(ingress_attested_at)
        AND ingress_attested_at = cutover_at
        AND (
            activated_at IS NULL
            OR (isfinite(activated_at) AND activated_at >= cutover_at)
        )
        AND (
            first_activity_at IS NULL
            OR (
                isfinite(first_activity_at)
                AND activated_at IS NOT NULL
                AND first_activity_at >= activated_at
            )
        )
        AND (
            rollback_quarantined_at IS NULL
            OR (
                isfinite(rollback_quarantined_at)
                AND activated_at IS NOT NULL
                AND rollback_quarantined_at >= activated_at
            )
        )
        AND (first_activity_at IS NULL OR rollback_quarantined_at IS NULL)
    )
);

-- This singleton is deliberately separate from the immutable cutover receipt.
-- It is the durable admission gate for *new* API-side authority writes.  The
-- API's SECURITY DEFINER recheck takes a SHARE lock on the one row, retaining
-- it until the caller's outer transaction commits.  An owner-side close takes
-- UPDATE, so it waits for every already-admitted write before closing the
-- gate; no new guarded write can pass once the close commits.
CREATE TABLE public.authority_admission_state (
    singleton boolean PRIMARY KEY CHECK (singleton),
    admissions_open boolean NOT NULL,
    changed_at timestamptz NOT NULL CHECK (isfinite(changed_at))
);

-- The migration role can itself be a non-owner subject to FORCE RLS.  The
-- receipt must count every historical row, not merely the migration session's
-- currently scoped tenant.
ALTER TABLE outcome_event NO FORCE ROW LEVEL SECURITY;
ALTER TABLE outcome_event DISABLE ROW LEVEL SECURITY;
INSERT INTO public.authority_cutover_state (
    singleton, cutover_at, ingress_attested_at, activated_at, first_activity_at,
    legacy_dead_letter_rows, legacy_outcome_rows
)
SELECT true, statement_timestamp(), statement_timestamp(), NULL, NULL,
       (SELECT count(*) FROM dead_letter WHERE authority_version = 0),
       (SELECT count(*) FROM outcome_event WHERE authority_version = 0);
INSERT INTO public.authority_admission_state (singleton, admissions_open, changed_at)
VALUES (true, false, statement_timestamp());
ALTER TABLE outcome_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE outcome_event FORCE ROW LEVEL SECURITY;

CREATE FUNCTION public.tracebed_mark_authority_activity() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM 1
      FROM public.authority_cutover_state
     WHERE singleton
       AND activated_at IS NOT NULL
       AND rollback_quarantined_at IS NULL
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority cutover is not activated' USING ERRCODE = '55000';
    END IF;
    UPDATE public.authority_cutover_state
       SET first_activity_at = COALESCE(first_activity_at, statement_timestamp())
     WHERE singleton AND rollback_quarantined_at IS NULL;
END;
$$;
CREATE FUNCTION public.tracebed_mark_authority_activity_trigger() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.tracebed_mark_authority_activity();
    RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.tracebed_mark_authority_activity() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.tracebed_mark_authority_activity_trigger() FROM PUBLIC;

-- Runtime identities intentionally have SELECT-only registry ACLs.  The
-- authority decision needs tuple locks so a concurrent revocation,
-- suspension, or deletion cannot commit between the recheck and its guarded
-- write.  Keep those owner-only locks in this tiny API-bound routine rather
-- than granting registry UPDATE merely to make SELECT ... FOR SHARE work.
CREATE FUNCTION public.tracebed_require_active_grant(
    expected_project_id uuid,
    expected_principal_id uuid,
    expected_agent_type_id uuid,
    expected_grant_id uuid,
    expected_role text,
    expected_feedback_source text
) RETURNS TABLE (grant_id uuid, role text, feedback_source text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- Only the credential-bearing API identity may invoke this narrow
    -- recheck.  SECURITY DEFINER changes current_user, so session_user is
    -- the non-forgeable caller identity to inspect here.
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR expected_project_id IS NULL
       OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL
       OR expected_grant_id IS NULL
       OR expected_role IS NULL
       OR expected_role NOT IN ('data', 'feedback', 'admin', 'export')
       OR (expected_role = 'feedback' AND (
               expected_feedback_source IS NULL
               OR expected_feedback_source NOT IN ('verdict', 'correction_adapter', 'downstream')
           ))
       OR (expected_role <> 'feedback' AND expected_feedback_source IS NOT NULL)
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'authority recheck denied' USING ERRCODE = '42501';
    END IF;

    -- Keep this tuple lock through the caller's scoped transaction.  Queue
    -- insert, retrieval run-open, and invalidation all invoke this routine
    -- before their authority-bearing mutation.  The owner close transition
    -- therefore forms a real admission fence rather than a best-effort
    -- process stop.
    PERFORM 1
      FROM public.authority_admission_state
     WHERE singleton
       AND admissions_open
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority admission is closed' USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT principal_grant.grant_id, principal_grant.role, principal_grant.feedback_source
      FROM public.principal AS principal
      JOIN public.agent_registration AS registration
        ON registration.principal_id = principal.principal_id
      JOIN public.project AS project ON project.project_id = registration.project_id
      JOIN public.agent_type AS agent_type
        ON agent_type.agent_type_id = registration.agent_type_id
       AND agent_type.project_id = registration.project_id
      JOIN public.principal_grant AS principal_grant
        ON principal_grant.project_id = registration.project_id
       AND principal_grant.principal_id = principal.principal_id
     WHERE principal.principal_id = expected_principal_id
       AND registration.project_id = expected_project_id
       AND registration.agent_type_id = expected_agent_type_id
       AND principal_grant.grant_id = expected_grant_id
       AND principal_grant.role = expected_role
       AND principal_grant.feedback_source IS NOT DISTINCT FROM expected_feedback_source
       AND principal.revoked_at IS NULL
       AND registration.revoked_at IS NULL
       AND project.status = 'active'
       AND project.deleted_at IS NULL
       AND principal_grant.revoked_at IS NULL
     FOR SHARE OF principal, registration, project, agent_type, principal_grant;
END;
$$;
REVOKE ALL ON FUNCTION public.tracebed_require_active_grant(uuid, uuid, uuid, uuid, text, text)
    FROM PUBLIC;

-- Owner-only lifecycle transitions are intentionally tiny and close over no
-- project, grant, or queue authority.  The controller invokes them only from
-- the fixed pg-admin network.  Their session_user checks keep the SECURITY
-- DEFINER owner from turning a broad function ACL into a runtime capability.
CREATE FUNCTION public.tracebed_close_authority_admission() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_owner' THEN
        RAISE EXCEPTION 'authority admission transition denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM public.authority_admission_state WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority admission state is missing' USING ERRCODE = '55000';
    END IF;
    -- API backends must be gone before an upgrade/rollback controller can
    -- claim its close receipt.  Existing admitted transactions hold SHARE
    -- and are waited out above; a stale idle API session is an unsafe
    -- lifecycle topology and is refused rather than terminated here.
    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_stat_activity
         WHERE pid <> pg_catalog.pg_backend_pid()
           AND usename = 'tracebed_api'
    ) THEN
        RAISE EXCEPTION 'authority admission close requires no API sessions'
            USING ERRCODE = '55000';
    END IF;
    UPDATE public.authority_admission_state
       SET admissions_open = false, changed_at = pg_catalog.statement_timestamp()
     WHERE singleton;
END;
$$;

CREATE FUNCTION public.tracebed_open_authority_admission() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_owner' THEN
        RAISE EXCEPTION 'authority admission transition denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1
      FROM public.authority_cutover_state
     WHERE singleton
       AND activated_at IS NOT NULL
       AND rollback_quarantined_at IS NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority admission open requires active cutover' USING ERRCODE = '55000';
    END IF;
    PERFORM 1 FROM public.authority_admission_state WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority admission state is missing' USING ERRCODE = '55000';
    END IF;
    UPDATE public.authority_admission_state
       SET admissions_open = true, changed_at = pg_catalog.statement_timestamp()
     WHERE singleton;
END;
$$;

CREATE FUNCTION public.tracebed_assert_authority_runtime_drained() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_owner' THEN
        RAISE EXCEPTION 'authority drain assertion denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1
      FROM public.authority_admission_state
     WHERE singleton
       AND NOT admissions_open
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority drain requires closed admission' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM public.work_queue
         WHERE authority_version = 1
           AND topic IN ('trace_event', 'outcome_event', 'memory_proposal')
    ) OR EXISTS (
        SELECT 1
          FROM pg_catalog.pg_stat_activity
         WHERE pid <> pg_catalog.pg_backend_pid()
           AND usename IN ('tracebed_api', 'tracebed_worker')
    ) THEN
        RAISE EXCEPTION 'authority runtime drain assertion failed' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- This is deliberately narrower than the drain assertion: publication
-- compensation needs a read-only owner proof that a failed pre-open attempt
-- did not expose authority admission.  It neither drains nor terminates a
-- runtime; the controller has already stopped partial services before asking
-- for this receipt.
CREATE FUNCTION public.tracebed_assert_authority_admission_closed() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_owner' THEN
        RAISE EXCEPTION 'authority admission assertion denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1
      FROM public.authority_admission_state
     WHERE singleton
       AND NOT admissions_open
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority admission is not closed' USING ERRCODE = '55000';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.tracebed_close_authority_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_open_authority_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_assert_authority_runtime_drained() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_assert_authority_admission_closed() FROM PUBLIC;

-- Tier-A finalization must keep each archive subject-key row stable while it
-- commits derived state.  The worker intentionally has no direct UPDATE on
-- key material, so this owner-held locking read preserves the shred race
-- fence without widening that credential's table mutation surface.
CREATE FUNCTION public.tracebed_lock_subject_bindings(
    expected_project_id uuid,
    expected_subject_tags text[]
) RETURNS TABLE (subject_tag text, key_id uuid, destroyed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR expected_project_id IS NULL
       OR expected_subject_tags IS NULL
       OR pg_catalog.cardinality(expected_subject_tags) NOT BETWEEN 1 AND 64
       OR EXISTS (
           SELECT 1
             FROM pg_catalog.unnest(expected_subject_tags) AS expected_tag(subject_tag)
            WHERE expected_tag.subject_tag IS NULL
               OR expected_tag.subject_tag = ''
               OR pg_catalog.char_length(expected_tag.subject_tag) > 128
       )
       OR (SELECT count(*) FROM pg_catalog.unnest(expected_subject_tags))
              <> (SELECT count(DISTINCT subject_tag)
                    FROM pg_catalog.unnest(expected_subject_tags) AS expected_tag(subject_tag))
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text
       OR (SELECT count(*)
             FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user
            )) <> 1
    THEN
        RAISE EXCEPTION 'subject binding lock denied' USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT key_row.subject_tag, key_row.key_id, key_row.destroyed_at
      FROM public.subject_key AS key_row
     WHERE key_row.project_id = expected_project_id
       AND key_row.subject_tag = ANY(expected_subject_tags)
     ORDER BY key_row.subject_tag
     FOR UPDATE;
END;
$$;
REVOKE ALL ON FUNCTION public.tracebed_lock_subject_bindings(uuid, text[])
    FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
         tracebed_api_group, tracebed_erasure_group;

-- The closed-state controller probe authenticates an already-started runtime
-- process before public authority admission opens.  It is read-only and has
-- no arguments: session_user is the credential boundary, so callers cannot
-- request another role's readiness profile.  Serving readiness wraps this
-- exact proof and additionally requires the admission singleton to be open.
CREATE FUNCTION public.tracebed_runtime_prepublication_readiness() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    expected_group text;
    role_state record;
BEGIN
    IF session_user = 'tracebed_api' THEN
        expected_group := 'tracebed_api_group';
    ELSIF session_user = 'tracebed_worker' THEN
        expected_group := 'tracebed_worker_group';
    ELSE
        RAISE EXCEPTION 'runtime readiness denied' USING ERRCODE = '42501';
    END IF;

    SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
           role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
           role.rolconfig, auth.rolpassword, auth.rolvaliduntil
      INTO role_state
      FROM pg_catalog.pg_roles AS role
      JOIN pg_catalog.pg_authid AS auth ON auth.oid = role.oid
     WHERE role.rolname = session_user;
    IF NOT FOUND OR NOT role_state.rolcanlogin OR role_state.rolsuper
       OR role_state.rolcreatedb OR role_state.rolcreaterole
       OR NOT role_state.rolinherit OR role_state.rolbypassrls OR role_state.rolreplication
       OR role_state.rolconnlimit <> -1 OR role_state.rolconfig IS NOT NULL
       OR role_state.rolpassword IS NULL OR role_state.rolpassword NOT LIKE 'SCRAM-SHA-256$%'
       OR role_state.rolvaliduntil IS NOT NULL
       OR (SELECT count(*)
             FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user)
          ) <> 1
       OR NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_auth_members AS membership
              JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
              JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
             WHERE granted.rolname = expected_group AND member.rolname = session_user
               AND membership.admin_option IS FALSE AND membership.inherit_option IS TRUE
               AND membership.set_option IS FALSE
       )
       OR EXISTS (
            SELECT 1
              FROM pg_catalog.pg_db_role_setting AS setting
             WHERE setting.setrole = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user)
       )
       OR NULLIF(pg_catalog.current_setting('tracebed.project_id', true), '') IS NOT NULL
       OR NOT EXISTS (
            SELECT 1
              FROM public.authority_cutover_state
             WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
       ) THEN
        RAISE EXCEPTION 'runtime readiness denied' USING ERRCODE = '42501';
    END IF;

    -- These owner-only assertions authenticate membership and every direct
    -- ACL/ownership tuple, not merely the handful checked above.
    PERFORM public.authority_acl_security_assert('cutover_0011');
    PERFORM public.authority_schema_security_assert('cutover_0011');
END;
$$;
CREATE FUNCTION public.tracebed_runtime_readiness() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.tracebed_runtime_prepublication_readiness();
    PERFORM 1
      FROM public.authority_admission_state
     WHERE singleton
       AND admissions_open
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runtime readiness denied' USING ERRCODE = '42501';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.tracebed_runtime_readiness() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_runtime_prepublication_readiness() FROM PUBLIC;

CREATE TRIGGER work_queue_authority_activity
    AFTER INSERT ON work_queue FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_authority_activity_trigger();
CREATE TRIGGER dead_letter_authority_activity
    AFTER INSERT ON dead_letter FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_authority_activity_trigger();
CREATE TRIGGER outcome_event_authority_activity
    AFTER INSERT ON outcome_event FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_authority_activity_trigger();
CREATE TRIGGER run_owner_authority_activity
    AFTER INSERT ON run_owner FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_authority_activity_trigger();

ALTER TABLE work_queue ALTER COLUMN authority_version DROP DEFAULT;
ALTER TABLE work_queue ALTER COLUMN subject_digests DROP DEFAULT;
ALTER TABLE work_queue DROP CONSTRAINT work_queue_authority_v0_v1_ck;
ALTER TABLE work_queue ADD CONSTRAINT work_queue_authority_v1_only_ck CHECK (
    authority_version IS NOT NULL AND authority_version = 1
    AND run_id IS NOT NULL AND source_principal_id IS NOT NULL
    AND source_agent_type_id IS NOT NULL AND source_grant_id IS NOT NULL
    AND required_role IS NOT NULL AND run_owner_principal_id IS NOT NULL
    AND run_owner_agent_type_id IS NOT NULL
    AND ((topic IN ('trace_event', 'memory_proposal') AND required_role = 'data'
          AND feedback_source IS NULL AND source_principal_id = run_owner_principal_id
          AND source_agent_type_id = run_owner_agent_type_id)
         OR (topic = 'outcome_event' AND required_role = 'feedback'
             AND feedback_source IS NOT NULL
             AND feedback_source IN ('verdict', 'correction_adapter', 'downstream')))
);
ALTER TABLE work_queue ADD CONSTRAINT work_queue_payload_object_ck
    CHECK (jsonb_typeof(payload) = 'object');
ALTER TABLE dead_letter ALTER COLUMN authority_version DROP DEFAULT;
ALTER TABLE dead_letter ALTER COLUMN subject_digests DROP DEFAULT;
CREATE FUNCTION public.dead_letter_require_authority_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.authority_version IS DISTINCT FROM 1
       OR jsonb_typeof(NEW.payload) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'new dead letters require authority version 1' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER dead_letter_require_authority_v1_guard
    BEFORE INSERT ON public.dead_letter FOR EACH ROW EXECUTE FUNCTION public.dead_letter_require_authority_v1();
ALTER TABLE outcome_event ALTER COLUMN authority_version DROP DEFAULT;
CREATE FUNCTION public.outcome_event_require_authority_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.authority_version IS DISTINCT FROM 1
       OR jsonb_typeof(NEW.payload) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'new outcomes require authority version 1' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER outcome_event_require_authority_v1_guard
    BEFORE INSERT ON public.outcome_event FOR EACH ROW EXECUTE FUNCTION public.outcome_event_require_authority_v1();

DO $$
DECLARE
    relation_name text;
    api_grant text;
    worker_grant text;
    child record;
    extension_schema text;
    extension_routine record;
    extension_type record;
BEGIN
    -- Public stays hardened even on a future rollback. Split groups get only
    -- connection/schema baseline before the explicit object matrix below.
    FOR extension_schema IN
        SELECT datname FROM pg_database
         WHERE datname IN (current_database(), 'postgres', 'template0', 'template1')
    LOOP
        EXECUTE format('REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC', extension_schema);
    END LOOP;
    REVOKE USAGE, CREATE ON SCHEMA public FROM PUBLIC;
    -- Do not use ON ALL ... here.  The authenticated source receipt has
    -- already established the complete 0010 profile; revoking the explicit
    -- PostgreSQL privilege alphabet per existing public object preserves the
    -- same public hardening without a wildcard ACL operation.
    FOR child IN
        SELECT relation.relname, relation.relkind
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
    LOOP
        EXECUTE format(
            'REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.%I FROM PUBLIC',
            child.relname
        );
    END LOOP;
    FOR child IN
        SELECT relation.relname
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public' AND relation.relkind = 'S'
    LOOP
        EXECUTE format('REVOKE USAGE, SELECT, UPDATE ON SEQUENCE public.%I FROM PUBLIC', child.relname);
    END LOOP;
    FOR extension_routine IN
        SELECT procedure.oid::regprocedure AS identity
          FROM pg_proc AS procedure
          JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'public'
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', extension_routine.identity);
    END LOOP;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM tracebed_app, tracebed_erasure_group', current_database());
    REVOKE USAGE ON SCHEMA public FROM tracebed_app;
    FOR child IN
        SELECT relation.relname, relation.relkind
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
    LOOP
        EXECUTE format(
            'REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.%I '
            || 'FROM tracebed_app, tracebed_api, tracebed_worker, tracebed_api_group, '
            || 'tracebed_worker_group, tracebed_erasure_group',
            child.relname
        );
    END LOOP;
    FOR child IN
        SELECT relation.relname
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public' AND relation.relkind = 'S'
    LOOP
        EXECUTE format(
            'REVOKE USAGE, SELECT, UPDATE ON SEQUENCE public.%I '
            || 'FROM tracebed_app, tracebed_api, tracebed_worker, tracebed_api_group, '
            || 'tracebed_worker_group, tracebed_erasure_group',
            child.relname
        );
    END LOOP;
    FOR extension_routine IN
        SELECT procedure.oid::regprocedure AS identity
          FROM pg_proc AS procedure
          JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'public'
    LOOP
        EXECUTE format(
            'REVOKE EXECUTE ON FUNCTION %s FROM tracebed_app, tracebed_api, tracebed_worker, '
            || 'tracebed_api_group, tracebed_worker_group, tracebed_erasure_group',
            extension_routine.identity
        );
    END LOOP;
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO tracebed_api_group, tracebed_worker_group', current_database());
    GRANT USAGE ON SCHEMA public TO tracebed_api_group, tracebed_worker_group;
    FOR extension_schema IN
        SELECT namespace.nspname
          FROM pg_extension AS extension
          JOIN pg_namespace AS namespace ON namespace.oid = extension.extnamespace
         WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema')
           AND namespace.nspname !~ '^pg_'
    LOOP
        EXECUTE format('REVOKE USAGE, CREATE ON SCHEMA %I FROM PUBLIC', extension_schema);
        IF extension_schema IN ('tokenizer_catalog', 'bm25_catalog') THEN
            EXECUTE format('REVOKE USAGE, CREATE ON SCHEMA %I FROM tracebed_app', extension_schema);
            IF extension_schema = 'tokenizer_catalog' THEN
                FOR child IN
                    SELECT relation.relname
                      FROM pg_class AS relation
                      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                     WHERE namespace.nspname = 'tokenizer_catalog' AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                LOOP
                    EXECUTE format(
                        'REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON tokenizer_catalog.%I '
                        || 'FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker, tracebed_api_group, '
                        || 'tracebed_worker_group, tracebed_erasure_group',
                        child.relname
                    );
                END LOOP;
            END IF;
            EXECUTE format(
                'GRANT USAGE ON SCHEMA %I TO tracebed_api_group, tracebed_worker_group', extension_schema
            );
        END IF;
    END LOOP;
    -- Strip the extension defaults first.  PostgreSQL grants PUBLIC EXECUTE
    -- to extension routines by default, so merely omitting a grant would
    -- still expose diagnostics such as bm25_page_inspect.
    FOR extension_routine IN
        SELECT procedure.oid::regprocedure AS identity
          FROM pg_proc AS procedure
          JOIN pg_depend AS member
            ON member.classid = 'pg_proc'::regclass
           AND member.objid = procedure.oid
           AND member.deptype = 'e'
          JOIN pg_extension AS extension ON extension.oid = member.refobjid
         WHERE extension.extname IN ('vector', 'pg_tokenizer', 'vchord_bm25')
    LOOP
        EXECUTE format(
            'REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, tracebed_app, tracebed_api, '
            || 'tracebed_worker, tracebed_api_group, tracebed_worker_group, tracebed_erasure_group',
            extension_routine.identity
        );
    END LOOP;
    FOR extension_type IN
        SELECT type.oid::regtype AS identity
          FROM pg_type AS type
          JOIN pg_depend AS member
            ON member.classid = 'pg_type'::regclass
           AND member.objid = type.oid
           AND member.deptype = 'e'
          JOIN pg_extension AS extension ON extension.oid = member.refobjid
         WHERE extension.extname IN ('vector', 'pg_tokenizer', 'vchord_bm25')
           AND type.typelem = 0
    LOOP
        EXECUTE format(
            'REVOKE USAGE ON TYPE %s FROM PUBLIC, tracebed_app, tracebed_api, '
            || 'tracebed_worker, tracebed_api_group, tracebed_worker_group, tracebed_erasure_group',
            extension_type.identity
        );
    END LOOP;
    -- This is intentionally a routine/type *allowlist*, not every extension
    -- member. API reads ranked lexical/vector results; worker writes lexical
    -- vectors and embeddings. Neither needs tokenizer administration nor
    -- page-level BM25 diagnostics.
    GRANT EXECUTE ON FUNCTION tokenizer_catalog.tokenize(text, text)
        TO tracebed_api_group, tracebed_worker_group;
    GRANT EXECUTE ON FUNCTION bm25_catalog._vchord_bm25_cast_array_to_bm25vector(
        integer[], integer, boolean
    ) TO tracebed_api_group, tracebed_worker_group;
    GRANT EXECUTE ON FUNCTION bm25_catalog.to_bm25query(regclass, bm25_catalog.bm25vector)
        TO tracebed_api_group;
    GRANT EXECUTE ON FUNCTION bm25_catalog.search_bm25query(
        bm25_catalog.bm25vector, bm25_catalog.bm25query
    ) TO tracebed_api_group;
    GRANT EXECUTE ON FUNCTION public.cosine_distance(halfvec, halfvec)
        TO tracebed_api_group;
    GRANT EXECUTE ON FUNCTION public.halfvec(halfvec, integer, boolean)
        TO tracebed_worker_group;
    GRANT USAGE ON TYPE public.halfvec, bm25_catalog.bm25vector, bm25_catalog.bm25query
        TO tracebed_api_group;
    GRANT USAGE ON TYPE public.halfvec, bm25_catalog.bm25vector TO tracebed_worker_group;
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'tokenizer_catalog') THEN
        GRANT SELECT (name, config) ON tokenizer_catalog.tokenizer, tokenizer_catalog.text_analyzer
            TO tracebed_api_group, tracebed_worker_group;
    END IF;

    FOREACH relation_name IN ARRAY ARRAY[
        'project', 'principal', 'agent_type', 'agent_registration', 'principal_grant',
        'project_config', 'agent_type_config'
    ] LOOP
        EXECUTE format('GRANT SELECT ON public.%I TO tracebed_api_group, tracebed_worker_group', relation_name);
    END LOOP;
    GRANT SELECT ON public.killswitch_state TO tracebed_api_group;
    GRANT SELECT, INSERT, UPDATE ON public.killswitch_state TO tracebed_worker_group;
    GRANT SELECT ON public.embedding_model, public.scoring_epoch TO tracebed_worker_group;
    GRANT SELECT, INSERT ON public.work_queue TO tracebed_api_group;
    GRANT USAGE, SELECT ON SEQUENCE public.work_queue_id_seq TO tracebed_api_group;
    GRANT SELECT, UPDATE, DELETE ON public.work_queue TO tracebed_worker_group;
    GRANT SELECT, INSERT ON public.dead_letter TO tracebed_worker_group;
    REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.authority_cutover_state FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
        tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.authority_admission_state FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
        tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    REVOKE EXECUTE ON FUNCTION public.subject_digests_are_valid(bytea[]) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.subject_digests_are_valid(bytea[])
        TO tracebed_api_group, tracebed_worker_group;
    REVOKE ALL ON FUNCTION public.tracebed_require_active_grant(uuid, uuid, uuid, uuid, text, text)
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
             tracebed_worker_group, tracebed_erasure_group;
    GRANT EXECUTE ON FUNCTION public.tracebed_require_active_grant(uuid, uuid, uuid, uuid, text, text)
        TO tracebed_api_group;
    REVOKE ALL ON FUNCTION public.tracebed_close_authority_admission()
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
             tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    REVOKE ALL ON FUNCTION public.tracebed_open_authority_admission()
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
             tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    REVOKE ALL ON FUNCTION public.tracebed_assert_authority_runtime_drained()
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
             tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    REVOKE ALL ON FUNCTION public.tracebed_assert_authority_admission_closed()
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
             tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    GRANT EXECUTE ON FUNCTION public.tracebed_close_authority_admission(),
                              public.tracebed_open_authority_admission(),
                              public.tracebed_assert_authority_runtime_drained(),
                              public.tracebed_assert_authority_admission_closed()
        TO tracebed_owner;
    REVOKE ALL ON FUNCTION public.tracebed_lock_subject_bindings(uuid, text[])
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
             tracebed_api_group, tracebed_erasure_group;
    GRANT EXECUTE ON FUNCTION public.tracebed_lock_subject_bindings(uuid, text[])
        TO tracebed_worker_group;
    REVOKE ALL ON FUNCTION public.tracebed_runtime_readiness()
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker, tracebed_erasure_group;
    REVOKE ALL ON FUNCTION public.tracebed_runtime_prepublication_readiness()
        FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker, tracebed_erasure_group;
    GRANT EXECUTE ON FUNCTION public.tracebed_runtime_readiness()
        TO tracebed_api_group, tracebed_worker_group;
    GRANT EXECUTE ON FUNCTION public.tracebed_runtime_prepublication_readiness()
        TO tracebed_api_group, tracebed_worker_group;

    FOR child IN
        SELECT relation.relname AS parent_name, relation.relname AS leaf_name
          FROM pg_class AS relation
          JOIN pg_namespace AS relation_schema ON relation_schema.oid = relation.relnamespace
         WHERE relation.relname IN (
            'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
            'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
            'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job','run_owner'
         ) AND relation_schema.nspname = 'public'
        UNION ALL
        SELECT parent.relname AS parent_name, leaf.relname AS leaf_name
          FROM pg_inherits AS inheritance
          JOIN pg_class AS leaf ON leaf.oid = inheritance.inhrelid
          JOIN pg_class AS parent ON parent.oid = inheritance.inhparent
          JOIN pg_namespace AS leaf_schema ON leaf_schema.oid = leaf.relnamespace
          JOIN pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace
         WHERE parent.relname IN (
            'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
            'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
            'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job','run_owner'
         ) AND leaf_schema.nspname = 'public' AND parent_schema.nspname = 'public'
    LOOP
        EXECUTE format(
            'REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.%I '
            || 'FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker, tracebed_api_group, '
            || 'tracebed_worker_group, tracebed_erasure_group',
            child.leaf_name
        );
        api_grant := CASE child.parent_name
            WHEN 'memory_item' THEN 'SELECT' WHEN 'memory_link' THEN 'SELECT'
            WHEN 'derived_state' THEN 'SELECT' WHEN 'trace_index' THEN 'SELECT'
            WHEN 'outcome_event' THEN 'SELECT' WHEN 'injection_log' THEN 'SELECT, INSERT'
            WHEN 'retrieval_event' THEN 'SELECT, INSERT' WHEN 'invalidation_event' THEN 'SELECT, INSERT'
            WHEN 'spend_ledger' THEN 'SELECT' WHEN 'review_queue' THEN 'SELECT'
            WHEN 'run_owner' THEN 'SELECT, INSERT' ELSE NULL END;
        worker_grant := CASE child.parent_name
            WHEN 'memory_item' THEN 'SELECT, INSERT, UPDATE' WHEN 'memory_link' THEN 'SELECT'
            WHEN 'derived_state' THEN 'SELECT, INSERT, DELETE' WHEN 'trace_index' THEN 'SELECT, INSERT, UPDATE'
            WHEN 'trace_subject' THEN 'SELECT, INSERT' WHEN 'subject_key' THEN 'SELECT, INSERT'
            WHEN 'outcome_event' THEN 'SELECT, INSERT' WHEN 'injection_log' THEN 'SELECT'
            WHEN 'retrieval_event' THEN 'SELECT' WHEN 'invalidation_event' THEN 'SELECT'
            WHEN 'spend_ledger' THEN 'SELECT, INSERT, UPDATE' WHEN 'review_queue' THEN 'SELECT, INSERT'
            WHEN 'memory_status_log' THEN 'SELECT, INSERT' WHEN 'memory_q_update' THEN 'SELECT, INSERT'
            WHEN 'trace_learning_job' THEN 'SELECT, INSERT, UPDATE' WHEN 'run_owner' THEN 'SELECT'
            ELSE NULL END;
        IF api_grant IS NOT NULL THEN
            EXECUTE format('GRANT %s ON public.%I TO tracebed_api_group', api_grant, child.leaf_name);
        END IF;
        IF worker_grant IS NOT NULL THEN
            EXECUTE format('GRANT %s ON public.%I TO tracebed_worker_group', worker_grant, child.leaf_name);
        END IF;
    END LOOP;
END
$$;

-- The cutover expected tuple set is part of 0010's checked-in immutable
-- canonical contract.  Never learn it from this live catalog.

-- This is the final authority mutation in the cutover transaction. The
-- append guard binds it to epoch 0 and derives all receipt metadata.
INSERT INTO public.authority_acl_epoch (
    epoch, profile, profile_version, source_acl_digest, result_acl_digest,
    source_schema_digest, result_schema_digest, yoyo_lock_repair
)
SELECT
    (SELECT COALESCE(max(epoch), -1) + 1 FROM public.authority_acl_epoch),
    'cutover_0011',
    2,
    (SELECT result_acl_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
    public.authority_acl_security_assert('cutover_0011'),
    (SELECT result_schema_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
    public.authority_schema_security_assert('cutover_0011'),
    CASE WHEN to_regclass('public.yoyo_lock') IS NULL
         THEN 'not_required'::public.authority_yoyo_lock_repair
         ELSE 'revoked'::public.authority_yoyo_lock_repair END;
