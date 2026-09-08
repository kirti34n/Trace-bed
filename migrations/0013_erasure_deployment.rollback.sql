-- depends: 0012_erasure_saga

SET LOCAL search_path = public, pg_catalog;

LOCK TABLE public.authority_admission_state, public.erasure_request,
           public.erasure_deployment_state, public.erasure_deployment_epoch
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    PERFORM public.erasure_deployment_security_assert();
    IF NOT EXISTS (
        SELECT 1 FROM public.authority_admission_state
         WHERE singleton AND admissions_open IS FALSE
    ) OR EXISTS (
        SELECT 1 FROM pg_stat_activity
         WHERE pid <> pg_backend_pid()
           AND usename IN ('tracebed_api', 'tracebed_worker', 'tracebed_erasure')
    ) OR EXISTS (
        SELECT 1 FROM public.erasure_request
         WHERE lease_token IS NOT NULL AND lease_expires_at > statement_timestamp()
    ) OR EXISTS (
        SELECT 1 FROM public.erasure_deployment_state
         WHERE singleton AND first_executor_activity_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'erasure deployment rollback requires closed preactivity drain'
            USING ERRCODE = '55000';
    END IF;
    UPDATE public.erasure_deployment_state
       SET rollback_quarantined_at = statement_timestamp()
     WHERE singleton AND rollback_quarantined_at IS NULL
       AND first_executor_activity_at IS NULL;
    ALTER ROLE tracebed_erasure NOLOGIN PASSWORD NULL;
    PERFORM pg_terminate_backend(pid)
      FROM pg_stat_activity
     WHERE pid <> pg_backend_pid() AND usename = 'tracebed_erasure';
    IF EXISTS (
        SELECT 1 FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND usename = 'tracebed_erasure'
    ) THEN
        RAISE EXCEPTION 'erasure deployment rollback could not terminate erasure sessions'
            USING ERRCODE = '55000';
    END IF;
END
$$;

-- Restore the exact c12 API/worker definitions before dropping the E4
-- manifest.  c12's profile deliberately requires an absent erasure login.
CREATE OR REPLACE FUNCTION public.tracebed_runtime_prepublication_readiness() RETURNS void
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
       )
       OR NOT EXISTS (
            SELECT 1
              FROM public.erasure_cutover_state
             WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
       ) THEN
        RAISE EXCEPTION 'runtime readiness denied' USING ERRCODE = '42501';
    END IF;

    PERFORM public.authority_acl_security_assert('cutover_0012');
    PERFORM public.authority_schema_security_assert('cutover_0012');
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_runtime_readiness() RETURNS void
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

CREATE OR REPLACE FUNCTION public.tracebed_open_authority_admission() RETURNS void
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

-- Restore c12's exact v2 writer procedure.  E4 temporarily admits the
-- internal project sentinel under an already-minted snapshot capability so
-- a terminal archive can establish its structural key; c12 itself permits
-- only a digest in the durable run union.
CREATE OR REPLACE FUNCTION public.tracebed_insert_subject_key_v2(
    expected_project_id uuid,
    expected_subject_digest bytea,
    expected_key_id uuid,
    expected_wrapped_kek bytea
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_key_id IS NULL
       OR expected_subject_digest IS NULL OR octet_length(expected_subject_digest) <> 32
       OR expected_wrapped_kek IS NULL OR octet_length(expected_wrapped_kek) <> 60
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text
       OR NOT EXISTS (
            SELECT 1
              FROM public.erasure_snapshot_capability AS capability
             WHERE capability.backend_pid = pg_catalog.pg_backend_pid()
               AND capability.transaction_id = pg_catalog.txid_current()
               AND capability.project_id = expected_project_id
               AND expected_subject_digest = ANY(capability.subject_digests)
       ) THEN
        RAISE EXCEPTION 'v2 subject key write denied' USING ERRCODE = '42501';
    END IF;
    INSERT INTO public.subject_key (
        project_id, subject_tag, subject_digest, wrap_version,
        key_id, wrapped_kek, created_at
    ) VALUES (
        expected_project_id, NULL, expected_subject_digest, 2,
        expected_key_id, expected_wrapped_kek, statement_timestamp()
    ) ON CONFLICT (project_id, subject_digest) DO NOTHING;
END;
$$;

-- Restore c12's exact primary-batch definition.  E4's project predicate is
-- a deployment-only compatibility correction; the closed preactivity rollback
-- must leave the authenticated c12 catalog byte-for-byte equivalent again.
CREATE OR REPLACE FUNCTION public.tracebed_erasure_primary_batch(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, requested_limit integer
) RETURNS TABLE (
    batch_code text, affected_rows bigint, remaining bigint,
    closure_revision bigint, postcondition_digest bytea
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    request_row public.erasure_request%ROWTYPE;
    changed_count bigint := 0;
    branch_count bigint := 0;
    left_count bigint;
    digest_value bytea;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF requested_limit NOT BETWEEN 1 AND 10000
       OR request_row.phase NOT IN ('crypto_erased','primary_purged','external_purged') THEN
        RAISE EXCEPTION 'erasure primary batch denied' USING ERRCODE = 'P0013';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'primary_purge'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'request_update'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'receipt_insert'
    );

    DELETE FROM public.work_queue AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.work_queue AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.dead_letter AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.dead_letter AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.trace_learning_job AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.trace_learning_job AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.outcome_event AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.outcome_event AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.injection_log AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.injection_log AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.retrieval_event AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.retrieval_event AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.blackboard_entry AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.blackboard_entry AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.trace_index AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.trace_index AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.run_owner AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.run_owner AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.memory_status_log AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.memory_status_log AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id
                              AND mem_set.request_id = expected_request_id
                              AND mem_set.memory_id = candidate.memory_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.memory_q_update AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.memory_q_update AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id
                              AND mem_set.request_id = expected_request_id
                              AND mem_set.memory_id = candidate.memory_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.review_queue AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.review_queue AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id
                              AND mem_set.request_id = expected_request_id
                              AND mem_set.memory_id = candidate.memory_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.memory_link AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.memory_link AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id
                              AND mem_set.request_id = expected_request_id
                              AND mem_set.memory_id IN (candidate.src_id, candidate.dst_id)))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.run_memory_binding AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.run_memory_binding AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id)
                OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id
                              AND mem_set.request_id = expected_request_id
                              AND mem_set.memory_id = candidate.memory_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.memory_item AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.memory_item AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.subject_digest = ANY(candidate.subject_digests)
                OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id
                              AND mem_set.request_id = expected_request_id
                              AND mem_set.memory_id = candidate.id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.trace_subject AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.trace_subject AS candidate
         WHERE candidate.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR candidate.subject_digest = request_row.subject_digest
                OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id
                              AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id))
         ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    DELETE FROM public.derived_state AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.derived_state AS candidate
         WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
    DELETE FROM public.invalidation_event AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.invalidation_event AS candidate
         WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
    UPDATE public.killswitch_state AS row SET evidence = NULL
     WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.killswitch_state AS candidate
         WHERE candidate.project_id = expected_project_id AND candidate.evidence IS NOT NULL
         ORDER BY candidate.ctid LIMIT requested_limit
     ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    IF request_row.scope = 'project' THEN
        DELETE FROM public.project_config AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.project_config AS candidate
             WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
        ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
        DELETE FROM public.agent_type_config AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.agent_type_config AS candidate
             WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
        ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
        DELETE FROM public.killswitch_state AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.killswitch_state AS candidate
             WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
        ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
    END IF;

    SELECT public.tracebed_erasure_primary_remaining(expected_project_id, expected_request_id) INTO left_count;
    -- A project request owns the catalog-wide LIST teardown as part of its
    -- one successful primary pass.  The helper refuses a missing/ambiguous
    -- child before the first committed drop; a retry after this transaction
    -- may observe all children absent and is safely idempotent.
    IF left_count = 0 AND request_row.scope = 'project' THEN
        PERFORM public.tracebed_erasure_drop_project_partitions(
            expected_project_id, expected_request_id, expected_generation,
            expected_lease_token, expected_owner
        );
        SELECT public.tracebed_erasure_primary_remaining(expected_project_id, expected_request_id) INTO left_count;
    END IF;
    digest_value := sha256(convert_to('tracebed.erasure-primary/v1','UTF8')
        || uuid_send(expected_project_id) || uuid_send(expected_request_id)
        || int8send(request_row.closure_revision) || request_row.closure_digest
        || int8send(left_count));
    IF left_count = 0
       AND NOT EXISTS (
            SELECT 1 FROM public.erasure_step_receipt
             WHERE project_id = expected_project_id AND request_id = expected_request_id
               AND step_code = 'postgres' AND result = 'succeeded'
               AND work_revision = request_row.closure_revision
       ) THEN
        IF request_row.phase = 'crypto_erased' THEN
            UPDATE public.erasure_request
               SET phase = 'primary_purged', last_code = 'in_progress',
                   updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
             WHERE project_id = expected_project_id AND request_id = expected_request_id;
        END IF;
        PERFORM public.tracebed_erasure_append_receipt(
            expected_project_id, expected_request_id, expected_generation, expected_lease_token,
            'postgres', 'succeeded', 'ok', changed_count, request_row.closure_revision, digest_value
        );
    END IF;
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert'
    );
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update'
    );
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'primary_purge'
    );
    RETURN QUERY SELECT 'postgres'::text, changed_count, left_count,
                        request_row.closure_revision, digest_value;
END;
$$;

DROP TRIGGER erasure_request_executor_activity ON public.erasure_request;
DROP TRIGGER erasure_deployment_state_immutable ON public.erasure_deployment_state;
DROP TRIGGER erasure_deployment_epoch_append_only ON public.erasure_deployment_epoch;
DROP FUNCTION public.tracebed_erasure_readiness();
DROP FUNCTION public.tracebed_erasure_admission_is_open();
DROP FUNCTION public.tracebed_erasure_prepublication_readiness();
DROP FUNCTION public.tracebed_erasure_run_subject_digests(uuid,uuid);
DROP FUNCTION public.tracebed_mark_erasure_executor_activity_trigger();
DROP FUNCTION public.tracebed_mark_erasure_executor_activity();
DROP FUNCTION public.erasure_deployment_epoch_append_guard();
DROP FUNCTION public.erasure_deployment_security_assert();
DROP FUNCTION public.erasure_deployment_actual_tuples();
DROP FUNCTION public.erasure_deployment_role_control_digest();
DROP FUNCTION public.erasure_deployment_authority_schema_digest();
DROP FUNCTION public.erasure_deployment_authority_acl_digest();
DROP FUNCTION public.erasure_deployment_state_guard();
DROP FUNCTION public.erasure_deployment_epoch_receipt(bigint,bigint,bytea,bytea,timestamp with time zone,name,name);
DROP FUNCTION public.erasure_deployment_manifest_digest();
DROP FUNCTION public.erasure_deployment_frame(bytea);
DROP TABLE public.erasure_deployment_state;
DROP TABLE public.erasure_deployment_epoch;
DROP TABLE public.erasure_deployment_tuple;

REVOKE ALL PRIVILEGES ON SCHEMA public FROM tracebed_erasure;
DO $$
BEGIN
    EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM tracebed_erasure', current_database());
END
$$;
REVOKE tracebed_erasure_group FROM tracebed_erasure;
DROP ROLE tracebed_erasure;

DO $$
BEGIN
    PERFORM public.authority_acl_security_assert('cutover_0012');
    PERFORM public.authority_schema_security_assert('cutover_0012');
END
$$;
