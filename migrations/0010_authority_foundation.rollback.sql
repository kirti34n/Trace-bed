-- Rollback is intentionally conservative.  A populated authority foundation
-- is a security/audit boundary and must be migrated forward, not silently
-- erased.  Deployment-owned NOLOGIN group roles are retained.
DO $$
DECLARE
    role_name text;
    role_state record;
    child_row record;
BEGIN
    PERFORM set_config('search_path', 'public, pg_catalog', true);
    LOCK TABLE project, principal, agent_type, agent_registration, principal_grant,
               run_owner, work_queue, dead_letter, outcome_event
        IN ACCESS EXCLUSIVE MODE;

    -- The rollback calls the profile assertion and receipt helpers below.
    -- Authenticate the complete closed helper surface *before* invoking any
    -- of them: a redefined framing helper must not be able to make a forged
    -- epoch-zero receipt removable.
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
               '506b6ba1056ee96a0aa8ec4e3a18b5c5918c07a4d459d4c665bebb5687ab74ed'),
              ('public.authority_acl_security_assert(public.authority_acl_profile)',
               '4a35bd197fe7c36df49288cf310cb6db3140bdcbae76e640df07d15013d38640'),
              ('public.authority_schema_profile_actual_tuples(public.authority_acl_profile)',
               '365480d3d06974a0acbd28f5dcc6e5aa4681c76777f3efe6ae74d19de05d6dfb'),
              ('public.authority_schema_security_assert(public.authority_acl_profile)',
               'edc64a6dbd45a2fe6c472f87e7b56d841b47ccc36cc191351c4046b4ecca9b35')
          ) AS expected(signature, digest)
          LEFT JOIN LATERAL (
              SELECT encode(sha256(convert_to(pg_get_functiondef(to_regprocedure(expected.signature)), 'UTF8')), 'hex') AS digest
          ) AS actual ON true
         WHERE actual.digest IS DISTINCT FROM expected.digest
    ) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses an unauthenticated digest helper'
            USING ERRCODE = '55000';
    END IF;

    -- The foundation may be removed only before any authority transition. A
    -- hardened/cutover history is durable evidence and must migrate forward.
    IF NOT (
        SELECT count(*) = 1
           AND min(epoch) = 0
           AND min(profile::text) = 'genuine_0010'
           AND bool_and(profile_version = 2)
           AND bool_and(octet_length(profile_contract_digest) = 32)
           AND bool_and(octet_length(source_acl_digest) = 32)
           AND bool_and(octet_length(result_acl_digest) = 32)
           AND bool_and(octet_length(source_schema_digest) = 32)
           AND bool_and(octet_length(result_schema_digest) = 32)
           AND bool_and(octet_length(previous_receipt_digest) = 32)
           AND bool_and(octet_length(receipt_digest) = 32)
          FROM public.authority_acl_epoch
    ) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses authority ACL history'
            USING ERRCODE = '55000';
    END IF;
    -- An epoch-zero row is not merely a shape marker: it is the authenticated
    -- self-baseline.  Recompute both current profile digests and the chained
    -- receipt before dropping the very helpers which make that verification
    -- possible.  A tampered source/result pair must never make an otherwise
    -- empty foundation erasable.
    IF NOT (
        SELECT profile = 'genuine_0010'::public.authority_acl_profile
           AND profile_version = 2
           AND profile_contract_digest = decode(
               '8420a2ef2badd4d5c2494ddc57c87a6e6b9460100f5bcd64a24cf18989d21668', 'hex'
           )
           AND source_acl_digest = result_acl_digest
           AND source_schema_digest = result_schema_digest
           AND result_acl_digest = public.authority_acl_security_assert('genuine_0010')
           AND result_schema_digest = public.authority_schema_security_assert('genuine_0010')
           AND previous_receipt_digest = decode(repeat('00', 32), 'hex')
           AND yoyo_lock_repair = 'not_required'::public.authority_yoyo_lock_repair
           AND receipt_digest = public.authority_acl_epoch_receipt(
               epoch, profile, profile_version, profile_contract_digest,
               source_acl_digest, result_acl_digest, source_schema_digest, result_schema_digest,
               yoyo_lock_repair, previous_receipt_digest, actor_session_user, actor_current_user,
               transitioned_at
           )
          FROM public.authority_acl_epoch
         WHERE epoch = 0
    ) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses an invalid authority receipt'
            USING ERRCODE = '55000';
    END IF;

    -- Rollback must be as conservative as forward installation.  In
    -- particular, never erase an operator's unrelated ACL while attempting
    -- to remove the narrow 0010 grant matrix.
    FOREACH role_name IN ARRAY ARRAY[
        'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
    ]
    LOOP
        SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit,
               rolbypassrls, rolreplication, rolconnlimit
          INTO role_state
          FROM pg_roles
         WHERE rolname = role_name;
        IF NOT FOUND
           OR role_state.rolcanlogin OR role_state.rolsuper OR role_state.rolcreatedb
           OR role_state.rolcreaterole OR role_state.rolinherit
           OR role_state.rolbypassrls OR role_state.rolreplication
           OR role_state.rolconnlimit <> -1 THEN
            RAISE EXCEPTION 'authority foundation rollback refuses unsafe group role'
                USING ERRCODE = '55000';
        END IF;
        IF EXISTS (
            SELECT 1
              FROM pg_auth_members AS membership
              JOIN pg_roles AS group_role
                ON group_role.oid = membership.member OR group_role.oid = membership.roleid
             WHERE group_role.rolname = role_name
        ) THEN
            RAISE EXCEPTION 'authority foundation rollback refuses group memberships'
                USING ERRCODE = '55000';
        END IF;
        IF EXISTS (
            SELECT 1
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
             WHERE owner.rolname = role_name
        ) THEN
            RAISE EXCEPTION 'authority foundation rollback refuses group ownership'
                USING ERRCODE = '55000';
        END IF;
    END LOOP;

    -- Check delegation before the exact allowlist is temporarily removed. A
    -- grant option (or a non-owner grantor) on an otherwise expected object
    -- must refuse rollback rather than being silently erased with the 0010
    -- ACLs below.
    IF EXISTS (
        SELECT 1
          FROM (
              SELECT database.datdba AS owner_oid, privilege.grantee,
                     privilege.grantor, privilege.is_grantable
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
              SELECT default_acl.defaclrole, privilege.grantee,
                     privilege.grantor, privilege.is_grantable
                FROM pg_default_acl AS default_acl
                CROSS JOIN LATERAL aclexplode(default_acl.defaclacl) AS privilege
          ) AS acl_entry
          JOIN pg_roles AS grantee ON grantee.oid = acl_entry.grantee
         WHERE grantee.rolname IN (
             'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
         )
           AND (acl_entry.is_grantable
                OR acl_entry.grantor IS DISTINCT FROM acl_entry.owner_oid)
    ) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses unsafe grant delegation'
            USING ERRCODE = '55000';
    END IF;

    -- Subtract exactly the grants introduced by 0010, still inside this
    -- migration transaction.  Any unexpected ACL remains in pg_shdepend and
    -- aborts the rollback; an abort restores these temporary revocations.
    EXECUTE format(
        'REVOKE CONNECT ON DATABASE %I FROM tracebed_api_group, tracebed_worker_group, tracebed_erasure_group',
        current_database()
    );
    REVOKE USAGE ON SCHEMA public FROM tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
    REVOKE SELECT ON project, principal, agent_type, agent_registration, principal_grant
        FROM tracebed_api_group, tracebed_worker_group;
    REVOKE SELECT, INSERT ON run_owner FROM tracebed_api_group;
    REVOKE SELECT ON run_owner FROM tracebed_worker_group;
    REVOKE SELECT, INSERT ON work_queue FROM tracebed_api_group;
    REVOKE USAGE, SELECT ON SEQUENCE work_queue_id_seq FROM tracebed_api_group;
    REVOKE SELECT, UPDATE, DELETE ON work_queue FROM tracebed_worker_group;
    REVOKE SELECT, INSERT ON dead_letter FROM tracebed_worker_group;
    REVOKE EXECUTE ON FUNCTION subject_digests_are_valid(bytea[])
        FROM tracebed_api_group, tracebed_worker_group;
    FOR child_row IN
        SELECT child.relname
          FROM pg_inherits AS inheritance
          JOIN pg_class AS child ON child.oid = inheritance.inhrelid
         WHERE inheritance.inhparent = 'run_owner'::regclass
    LOOP
        EXECUTE format('REVOKE SELECT, INSERT ON %I FROM tracebed_api_group', child_row.relname);
        EXECUTE format('REVOKE SELECT ON %I FROM tracebed_worker_group', child_row.relname);
    END LOOP;
    IF EXISTS (
        SELECT 1
          FROM pg_shdepend AS dependency
          JOIN pg_roles AS dependent_role ON dependent_role.oid = dependency.refobjid
         WHERE dependent_role.rolname IN (
             'tracebed_api_group', 'tracebed_worker_group', 'tracebed_erasure_group'
         )
           AND dependency.refclassid = 'pg_authid'::regclass
           AND dependency.deptype IN ('a', 'i', 'r', 't', 'o')
    ) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses unexpected group access dependencies'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (SELECT 1 FROM principal_grant) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses principal grants' USING ERRCODE = '55000';
    END IF;
    -- Check every attached/default/orphan-bound child rather than iterating
    -- registry projects. FORCE RLS would otherwise hide rows whose project
    -- UUID has no registry row, and a successful rollback would erase them.
    ALTER TABLE run_owner NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE run_owner DISABLE ROW LEVEL SECURITY;
    IF EXISTS (SELECT 1 FROM run_owner) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses run owners' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM work_queue WHERE authority_version = 1)
       OR EXISTS (SELECT 1 FROM dead_letter WHERE authority_version = 1) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses v1 authority rows' USING ERRCODE = '55000';
    END IF;
    -- ``outcome_event`` is FORCE RLS too. Its v1 provenance columns may not
    -- be stripped merely because a non-superuser migration owner has no
    -- project GUC for an orphan/default/policy-drifted child.
    ALTER TABLE outcome_event NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE outcome_event DISABLE ROW LEVEL SECURITY;
    IF EXISTS (SELECT 1 FROM outcome_event WHERE authority_version = 1) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses v1 authority rows' USING ERRCODE = '55000';
    END IF;
    ALTER TABLE outcome_event ENABLE ROW LEVEL SECURITY;
    ALTER TABLE outcome_event FORCE ROW LEVEL SECURITY;
    IF EXISTS (SELECT 1 FROM work_queue WHERE cardinality(subject_digests) <> 0)
       OR EXISTS (SELECT 1 FROM dead_letter WHERE cardinality(subject_digests) <> 0) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses subject digests' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM agent_registration WHERE revoked_at IS NOT NULL) THEN
        RAISE EXCEPTION 'authority foundation rollback refuses revoked registrations' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM project WHERE status = 'deleting') THEN
        RAISE EXCEPTION 'authority foundation rollback refuses deleting projects' USING ERRCODE = '55000';
    END IF;

    DROP TABLE IF EXISTS run_owner CASCADE;
    DROP TABLE IF EXISTS principal_grant CASCADE;
    DROP FUNCTION IF EXISTS run_owner_enforce_immutability();
    DROP FUNCTION IF EXISTS principal_grant_enforce_immutability();

    ALTER TABLE outcome_event DROP CONSTRAINT IF EXISTS outcome_event_authority_v0_v1_ck;
    ALTER TABLE outcome_event DROP CONSTRAINT IF EXISTS outcome_event_authority_version_ck;
    ALTER TABLE outcome_event
        DROP COLUMN IF EXISTS run_owner_agent_type_id,
        DROP COLUMN IF EXISTS run_owner_principal_id,
        DROP COLUMN IF EXISTS feedback_source,
        DROP COLUMN IF EXISTS source_grant_id,
        DROP COLUMN IF EXISTS source_agent_type_id,
        DROP COLUMN IF EXISTS authority_version;

    DROP INDEX IF EXISTS dead_letter_subject_digests_gin_idx;
    DROP INDEX IF EXISTS dead_letter_project_run_id_idx;
    ALTER TABLE dead_letter DROP CONSTRAINT IF EXISTS dead_letter_authority_v0_v1_ck;
    ALTER TABLE dead_letter DROP CONSTRAINT IF EXISTS dead_letter_authority_version_ck;
    ALTER TABLE dead_letter DROP CONSTRAINT IF EXISTS dead_letter_subject_digests_ck;
    ALTER TABLE dead_letter
        DROP COLUMN IF EXISTS subject_digests,
        DROP COLUMN IF EXISTS run_owner_agent_type_id,
        DROP COLUMN IF EXISTS run_owner_principal_id,
        DROP COLUMN IF EXISTS feedback_source,
        DROP COLUMN IF EXISTS required_role,
        DROP COLUMN IF EXISTS source_grant_id,
        DROP COLUMN IF EXISTS source_agent_type_id,
        DROP COLUMN IF EXISTS source_principal_id,
        DROP COLUMN IF EXISTS run_id,
        DROP COLUMN IF EXISTS authority_version;

    DROP INDEX IF EXISTS work_queue_subject_digests_gin_idx;
    DROP INDEX IF EXISTS work_queue_project_run_id_idx;
    DROP INDEX IF EXISTS work_queue_project_id_idx;
    ALTER TABLE work_queue DROP CONSTRAINT IF EXISTS work_queue_authority_v0_v1_ck;
    ALTER TABLE work_queue DROP CONSTRAINT IF EXISTS work_queue_authority_version_ck;
    ALTER TABLE work_queue DROP CONSTRAINT IF EXISTS work_queue_subject_digests_ck;
    ALTER TABLE work_queue
        DROP COLUMN IF EXISTS subject_digests,
        DROP COLUMN IF EXISTS run_owner_agent_type_id,
        DROP COLUMN IF EXISTS run_owner_principal_id,
        DROP COLUMN IF EXISTS feedback_source,
        DROP COLUMN IF EXISTS required_role,
        DROP COLUMN IF EXISTS source_grant_id,
        DROP COLUMN IF EXISTS source_agent_type_id,
        DROP COLUMN IF EXISTS source_principal_id,
        DROP COLUMN IF EXISTS run_id,
        DROP COLUMN IF EXISTS authority_version;
    DROP FUNCTION IF EXISTS subject_digests_are_valid(bytea[]);

    DROP TRIGGER IF EXISTS agent_registration_immutability_guard ON agent_registration;
    DROP FUNCTION IF EXISTS agent_registration_enforce_immutability();
    ALTER TABLE agent_registration
        DROP CONSTRAINT IF EXISTS agent_registration_revocation_time_ck,
        DROP CONSTRAINT IF EXISTS agent_registration_agent_type_project_fk,
        DROP CONSTRAINT IF EXISTS agent_registration_principal_project_uq,
        DROP COLUMN IF EXISTS revoked_at;
    DROP TRIGGER IF EXISTS agent_type_immutability_guard ON agent_type;
    DROP FUNCTION IF EXISTS agent_type_enforce_immutability();
    ALTER TABLE agent_type DROP CONSTRAINT IF EXISTS agent_type_project_identity_uq;

    DROP TRIGGER IF EXISTS principal_immutability_guard ON principal;
    DROP FUNCTION IF EXISTS principal_enforce_immutability();
    ALTER TABLE principal DROP CONSTRAINT IF EXISTS principal_revocation_time_ck;

    DROP TRIGGER IF EXISTS project_lifecycle_guard ON project;
    DROP FUNCTION IF EXISTS project_enforce_lifecycle();
    ALTER TABLE project DROP CONSTRAINT IF EXISTS project_status_check;
    ALTER TABLE project DROP CONSTRAINT IF EXISTS project_deleted_at_shape_ck;
    ALTER TABLE project
        ADD CONSTRAINT project_status_check CHECK (status IN ('active', 'suspended', 'deleted'));

    DROP TRIGGER authority_acl_epoch_append_guard ON public.authority_acl_epoch;
    DROP TABLE public.authority_acl_epoch;
    DROP FUNCTION public.authority_acl_epoch_append_guard();
    DROP FUNCTION public.authority_schema_security_assert(public.authority_acl_profile);
    DROP FUNCTION public.authority_acl_security_assert(public.authority_acl_profile);
    DROP FUNCTION public.authority_schema_profile_actual_tuples(public.authority_acl_profile);
    DROP FUNCTION public.authority_acl_profile_actual_tuples(public.authority_acl_profile);
    DROP TABLE public.authority_acl_profile_tuple;
    DROP FUNCTION public.authority_acl_profile_tuple_guard();
    DROP FUNCTION public.authority_acl_epoch_receipt(
        bigint, public.authority_acl_profile, integer, bytea, bytea, bytea,
        bytea, bytea, public.authority_yoyo_lock_repair, bytea, name, name, timestamptz
    );
    DROP FUNCTION public.authority_acl_set_digest(bytea[]);
    DROP FUNCTION public.authority_acl_frame(bytea);
    DROP TYPE public.authority_yoyo_lock_repair;
    DROP TYPE public.authority_acl_profile;
END
$$;
