-- depends: 0012_erasure_saga

-- E4 is a new authenticated deployment epoch.  c12 intentionally records
-- that the erasure LOGIN is absent, so adding a role as a bootstrap-only
-- overlay would invalidate every API/worker readiness check.  This migration
-- therefore stages the role, the fixed deployment manifest, and a receipt
-- rooted in the latest c12 authority epoch before bootstrap publishes LOGIN.

SET LOCAL search_path = public, pg_catalog;

DO $$
DECLARE
    expected_history constant jsonb := (
        '["0001_registries","0002_partitioned","0003_rls","0004_lifecycle",'
        || '"0005_bm25","0006_q_update_ledger","0007_project_provisioning",'
        || '"0008_trace_learning_job","0009_trace_index_terminal_freeze",'
        || '"0010_authority_foundation","0011_authority_cutover","0012_erasure_saga"]'
    )::jsonb;
BEGIN
    IF current_setting('tracebed.atomic_migration_runner', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.ingress_quarantined', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.cluster_scope', true) IS DISTINCT FROM 'dedicated'
       OR session_user IS DISTINCT FROM current_user
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'erasure deployment requires the authenticated atomic owner runner'
            USING ERRCODE = '55000';
    END IF;
    IF (SELECT jsonb_agg(migration_id ORDER BY migration_id) FROM _yoyo_migration) IS DISTINCT FROM expected_history
       OR (SELECT count(*) FROM _yoyo_migration) <> 12
       OR EXISTS (
           SELECT 1
             FROM _yoyo_migration
            WHERE migration_id = '0012_erasure_saga'
              AND migration_hash <> 'cc6543ec143f8d79a7a3eca8001feaf0e62b3f29b417f8b636fa74004154eae6'
       ) THEN
        RAISE EXCEPTION 'erasure deployment requires the exact c12 yoyo history'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tracebed_erasure') THEN
        RAISE EXCEPTION 'erasure deployment refuses an existing erasure login'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.authority_admission_state
         WHERE singleton AND admissions_open IS FALSE
    ) OR NOT EXISTS (
        SELECT 1 FROM public.authority_cutover_state
         WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM public.erasure_cutover_state
         WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
    ) THEN
        RAISE EXCEPTION 'erasure deployment requires closed active c12 admission'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_stat_activity
         WHERE pid <> pg_backend_pid()
           AND usename IN ('tracebed_app', 'tracebed_api', 'tracebed_worker', 'tracebed_erasure')
    ) OR EXISTS (
        SELECT 1 FROM public.erasure_request
         WHERE lease_token IS NOT NULL AND lease_expires_at > statement_timestamp()
    ) THEN
        RAISE EXCEPTION 'erasure deployment requires no runtime sessions or live erasure leases'
            USING ERRCODE = '55000';
    END IF;
    PERFORM public.authority_acl_security_assert('cutover_0012');
    PERFORM public.authority_schema_security_assert('cutover_0012');
    IF NOT EXISTS (
        SELECT 1 FROM public.authority_acl_epoch
         WHERE epoch = (SELECT max(epoch) FROM public.authority_acl_epoch)
           AND profile = 'cutover_0012'::public.authority_acl_profile
    ) THEN
        RAISE EXCEPTION 'erasure deployment requires the latest c12 authority epoch'
            USING ERRCODE = '55000';
    END IF;
END
$$;

LOCK TABLE public.authority_admission_state, public.authority_acl_epoch,
           public.erasure_cutover_state, public.erasure_request
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    CREATE ROLE tracebed_erasure
        NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
        CONNECTION LIMIT -1;
    ALTER ROLE tracebed_erasure RESET ALL;
    GRANT tracebed_erasure_group TO tracebed_erasure
        WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
    -- c11 deliberately revoked the staged executor group's database route.
    -- E4 restores only the direct connection and namespace privileges needed
    -- to execute its reviewed, EXECUTE-only public procedures.
    EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM tracebed_erasure', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO tracebed_erasure', current_database());
    REVOKE ALL PRIVILEGES ON SCHEMA public FROM tracebed_erasure;
    GRANT USAGE ON SCHEMA public TO tracebed_erasure;
END
$$;

CREATE TABLE public.erasure_deployment_tuple (
    tuple_name text PRIMARY KEY CHECK (tuple_name ~ '^[a-z0-9_.:()/,-]+$'),
    tuple_digest bytea NOT NULL CHECK (octet_length(tuple_digest) = 32)
);
ALTER TABLE public.erasure_deployment_tuple ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_deployment_tuple FORCE ROW LEVEL SECURITY;
CREATE POLICY erasure_deployment_tuple_owner_only ON public.erasure_deployment_tuple
    USING (current_user = 'tracebed_owner')
    WITH CHECK (current_user = 'tracebed_owner');

CREATE TABLE public.erasure_deployment_epoch (
    epoch bigint PRIMARY KEY CHECK (epoch = 0),
    profile text NOT NULL CHECK (profile = 'deployment_0013'),
    parent_authority_epoch bigint NOT NULL CHECK (parent_authority_epoch >= 0),
    parent_authority_receipt bytea NOT NULL CHECK (octet_length(parent_authority_receipt) = 32),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
    receipt_digest bytea NOT NULL CHECK (octet_length(receipt_digest) = 32),
    transitioned_at timestamptz NOT NULL CHECK (isfinite(transitioned_at)),
    actor_session_user name NOT NULL,
    actor_current_user name NOT NULL,
    CHECK (actor_session_user = 'tracebed_owner' AND actor_current_user = 'tracebed_owner')
);
ALTER TABLE public.erasure_deployment_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_deployment_epoch FORCE ROW LEVEL SECURITY;
CREATE POLICY erasure_deployment_epoch_owner_only ON public.erasure_deployment_epoch
    USING (current_user = 'tracebed_owner')
    WITH CHECK (current_user = 'tracebed_owner');

CREATE TABLE public.erasure_deployment_state (
    singleton boolean PRIMARY KEY CHECK (singleton),
    epoch bigint NOT NULL UNIQUE REFERENCES public.erasure_deployment_epoch(epoch),
    staged_at timestamptz NOT NULL CHECK (isfinite(staged_at)),
    activated_at timestamptz,
    first_executor_activity_at timestamptz,
    rollback_quarantined_at timestamptz,
    CHECK (
        (activated_at IS NULL OR (isfinite(activated_at) AND activated_at >= staged_at))
        AND (first_executor_activity_at IS NULL OR (
            activated_at IS NOT NULL AND isfinite(first_executor_activity_at)
            AND first_executor_activity_at >= activated_at
        ))
        AND (rollback_quarantined_at IS NULL OR (
            activated_at IS NOT NULL AND isfinite(rollback_quarantined_at)
            AND rollback_quarantined_at >= activated_at
        ))
        AND NOT (first_executor_activity_at IS NOT NULL AND rollback_quarantined_at IS NOT NULL)
    )
);
ALTER TABLE public.erasure_deployment_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_deployment_state FORCE ROW LEVEL SECURITY;
CREATE POLICY erasure_deployment_state_owner_only ON public.erasure_deployment_state
    USING (current_user = 'tracebed_owner')
    WITH CHECK (current_user = 'tracebed_owner');

CREATE FUNCTION public.erasure_deployment_frame(value bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT int8send(octet_length(value)) || value
$$;

CREATE FUNCTION public.erasure_deployment_manifest_digest() RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT sha256(convert_to('tracebed.erasure-deployment-manifest/v1', 'UTF8')
                  || COALESCE(string_agg(
                      public.erasure_deployment_frame(convert_to(tuple_name, 'UTF8'))
                      || public.erasure_deployment_frame(tuple_digest),
                      ''::bytea ORDER BY tuple_name
                  ), ''::bytea))
      FROM public.erasure_deployment_tuple
$$;

CREATE FUNCTION public.erasure_deployment_epoch_receipt(
    epoch_value bigint,
    parent_epoch bigint,
    parent_receipt bytea,
    manifest bytea,
    transitioned timestamptz,
    actor_session name,
    actor_current name
) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT sha256(convert_to('tracebed.erasure-deployment-epoch/v1', 'UTF8')
                  || public.erasure_deployment_frame(int8send(epoch_value))
                  || public.erasure_deployment_frame(int8send(parent_epoch))
                  || public.erasure_deployment_frame(parent_receipt)
                  || public.erasure_deployment_frame(manifest)
                  -- A deployment receipt must name the instant, not the
                  -- caller's display of it.  ``timestamptz::text`` changes
                  -- with TimeZone even for the same stored value; binary
                  -- PostgreSQL timestamptz encoding is invariant and matches
                  -- the E3 receipt framing convention.
                  || public.erasure_deployment_frame(timestamptz_send(transitioned))
                  || public.erasure_deployment_frame(convert_to(actor_session::text, 'UTF8'))
                  || public.erasure_deployment_frame(convert_to(actor_current::text, 'UTF8')))
$$;

CREATE FUNCTION public.erasure_deployment_state_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR session_user NOT IN ('tracebed_owner', 'tracebed_erasure') THEN
        RAISE EXCEPTION 'erasure deployment state is append-only' USING ERRCODE = '42501';
    END IF;
    IF NEW.singleton IS DISTINCT FROM OLD.singleton OR NEW.epoch IS DISTINCT FROM OLD.epoch
       OR NEW.staged_at IS DISTINCT FROM OLD.staged_at THEN
        RAISE EXCEPTION 'erasure deployment state is immutable' USING ERRCODE = '42501';
    END IF;
    IF OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at
       OR OLD.first_executor_activity_at IS NOT NULL
          AND NEW.first_executor_activity_at IS DISTINCT FROM OLD.first_executor_activity_at
       OR OLD.rollback_quarantined_at IS NOT NULL
          AND NEW.rollback_quarantined_at IS DISTINCT FROM OLD.rollback_quarantined_at THEN
        RAISE EXCEPTION 'erasure deployment state is immutable' USING ERRCODE = '42501';
    END IF;
    IF NEW.activated_at IS NOT NULL AND OLD.activated_at IS NULL AND session_user <> 'tracebed_owner' THEN
        RAISE EXCEPTION 'erasure deployment activation denied' USING ERRCODE = '42501';
    END IF;
    IF NEW.first_executor_activity_at IS NOT NULL AND OLD.first_executor_activity_at IS NULL
       AND session_user <> 'tracebed_erasure' THEN
        RAISE EXCEPTION 'erasure deployment activity denied' USING ERRCODE = '42501';
    END IF;
    IF NEW.rollback_quarantined_at IS NOT NULL AND OLD.rollback_quarantined_at IS NULL
       AND session_user <> 'tracebed_owner' THEN
        RAISE EXCEPTION 'erasure deployment rollback denied' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER erasure_deployment_state_immutable
    BEFORE UPDATE OR DELETE ON public.erasure_deployment_state
    FOR EACH ROW EXECUTE FUNCTION public.erasure_deployment_state_guard();

CREATE FUNCTION public.tracebed_mark_erasure_executor_activity() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_erasure' THEN
        RETURN;
    END IF;
    UPDATE public.erasure_deployment_state
       SET first_executor_activity_at = statement_timestamp()
     WHERE singleton
       AND activated_at IS NOT NULL
       AND first_executor_activity_at IS NULL
       AND rollback_quarantined_at IS NULL;
    IF NOT FOUND AND NOT EXISTS (
        SELECT 1 FROM public.erasure_deployment_state
         WHERE singleton
           AND activated_at IS NOT NULL
           AND first_executor_activity_at IS NOT NULL
           AND rollback_quarantined_at IS NULL
    ) THEN
        RAISE EXCEPTION 'erasure deployment activity denied' USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE FUNCTION public.tracebed_mark_erasure_executor_activity_trigger() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    PERFORM public.tracebed_mark_erasure_executor_activity();
    RETURN COALESCE(NEW, OLD);
END
$$;

CREATE TRIGGER erasure_request_executor_activity
    BEFORE INSERT OR UPDATE OR DELETE ON public.erasure_request
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_executor_activity_trigger();

-- A terminal archive always has project-attributed structural sections
-- (run_start/run_end), even when its durable run union has concrete subject
-- digests.  c12's initial v2-key procedure admits only the latter, which
-- leaves a newly provisioned project's project sentinel unable to be created
-- by the first such archive.  E4 retains the c12 snapshot capability and
-- adds exactly the internal project sentinel as a second permissible key;
-- it does not permit a worker to mint an arbitrary subject key.
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
               AND (
                   expected_subject_digest = ANY(capability.subject_digests)
                   OR expected_subject_digest = public.tracebed_subject_digest(
                       expected_project_id, '__project__'
                   )
               )
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

-- The c12 durable write assertion deliberately re-derives and compares the
-- complete run union.  Its former Python-side query needed raw SELECT on
-- trace_subject, an ACL that the c12 worker profile correctly does not hold.
-- This narrow E4 reader returns only the canonical opaque union.  Callers
-- immediately pass it to the existing c12 assertion, which re-derives it
-- under the canonical project/run/fence locks before permitting a write.
CREATE FUNCTION public.tracebed_erasure_run_subject_digests(
    expected_project_id uuid,
    expected_run_id uuid
) RETURNS bytea[]
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    actual_digests bytea[];
BEGIN
    IF session_user NOT IN ('tracebed_api', 'tracebed_worker')
       OR expected_project_id IS NULL OR expected_run_id IS NULL
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'erasure run digest reader denied' USING ERRCODE = '42501';
    END IF;
    SELECT COALESCE(
               array_agg(binding.subject_digest ORDER BY binding.subject_digest),
               ARRAY[public.tracebed_subject_digest(expected_project_id, '__project__')]::bytea[]
           )
      INTO actual_digests
     FROM public.trace_subject AS binding
     WHERE binding.project_id = expected_project_id
       AND binding.run_id = expected_run_id;
    RETURN actual_digests;
END;
$$;

-- E4 keeps the accepted c12 source immutable.  PostgreSQL ctid values are
-- physical locations local to each partition, so an outer mutation that
-- matches only ctid can see an identically-numbered row in another project
-- leaf.  Rechecking the exact project in every outer DELETE/UPDATE preserves
-- the bounded ctid selection while making cross-leaf mutation impossible.
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

    DELETE FROM public.work_queue AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.dead_letter AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.trace_learning_job AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.outcome_event AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.injection_log AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.retrieval_event AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.blackboard_entry AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.trace_index AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.run_owner AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.memory_status_log AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.memory_q_update AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.review_queue AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.memory_link AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.run_memory_binding AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.memory_item AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.trace_subject AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

    DELETE FROM public.derived_state AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
        SELECT candidate.ctid FROM public.derived_state AS candidate
         WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
    DELETE FROM public.invalidation_event AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
        SELECT candidate.ctid FROM public.invalidation_event AS candidate
         WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
    ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
    UPDATE public.killswitch_state AS row SET evidence = NULL
     WHERE row.project_id = expected_project_id AND row.ctid IN (
        SELECT candidate.ctid FROM public.killswitch_state AS candidate
         WHERE candidate.project_id = expected_project_id AND candidate.evidence IS NOT NULL
         ORDER BY candidate.ctid LIMIT requested_limit
     ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;

    IF request_row.scope = 'project' THEN
        DELETE FROM public.project_config AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
            SELECT candidate.ctid FROM public.project_config AS candidate
             WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
        ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
        DELETE FROM public.agent_type_config AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
            SELECT candidate.ctid FROM public.agent_type_config AS candidate
             WHERE candidate.project_id = expected_project_id ORDER BY candidate.ctid LIMIT requested_limit
        ); GET DIAGNOSTICS branch_count = ROW_COUNT; changed_count := changed_count + branch_count;
        DELETE FROM public.killswitch_state AS row WHERE row.project_id = expected_project_id AND row.ctid IN (
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

-- E4 deliberately supersedes c12's ``erasure-login-absent`` fact, so its
-- readiness cannot call the old c12 assertion unchanged.  It must still
-- bind the complete current c12 ACL/schema surfaces, including every live
-- role, PUBLIC grant, default ACL, partition-normalized authority object,
-- and owner/function definition which those canonical profile routines
-- cover.  These set digests are materialized only after c12 was first
-- authenticated above and all reviewed E4 deltas below have been installed;
-- they are therefore successor profiles, not a learn-on-retry snapshot.
CREATE FUNCTION public.erasure_deployment_authority_acl_digest() RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.authority_acl_set_digest(
        COALESCE(array_agg(actual.tuple_digest ORDER BY actual.tuple_digest), ARRAY[]::bytea[])
    )
      FROM public.authority_acl_profile_actual_tuples(
          'cutover_0012'::public.authority_acl_profile
      ) AS actual(tuple_digest)
$$;

CREATE FUNCTION public.erasure_deployment_authority_schema_digest() RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.authority_acl_set_digest(
        COALESCE(array_agg(actual.tuple_digest ORDER BY actual.tuple_digest), ARRAY[]::bytea[])
    )
      FROM public.authority_schema_profile_actual_tuples(
          'cutover_0012'::public.authority_acl_profile
      ) AS actual(tuple_digest)
$$;

-- The c12 profiles intentionally predate the E4 LOGIN and therefore do not
-- enumerate its direct membership/settings/ownership control plane.  Bind
-- that complete local graph separately.  The LOGIN verifier itself is a
-- staged publication value, so it is represented as an allowed no-login or
-- SCRAM shape rather than copied into the immutable receipt.
CREATE FUNCTION public.erasure_deployment_role_control_digest() RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
WITH protected_role AS (
    SELECT role.oid, role.rolname, role.rolcanlogin, role.rolsuper,
           role.rolcreatedb, role.rolcreaterole, role.rolinherit,
           role.rolbypassrls, role.rolreplication, role.rolconnlimit,
           role.rolconfig, auth.rolpassword, auth.rolvaliduntil
      FROM pg_catalog.pg_roles AS role
      JOIN pg_catalog.pg_authid AS auth ON auth.oid = role.oid
     WHERE role.rolname IN ('tracebed_erasure', 'tracebed_erasure_group')
), ownership(owner_oid, class_name, object_name) AS (
    SELECT database.datdba, 'database', database.datname FROM pg_catalog.pg_database AS database
    UNION ALL SELECT tablespace.spcowner, 'tablespace', tablespace.spcname FROM pg_catalog.pg_tablespace AS tablespace
    UNION ALL SELECT namespace.nspowner, 'schema', namespace.nspname FROM pg_catalog.pg_namespace AS namespace
    UNION ALL SELECT relation.relowner, 'relation', namespace.nspname || '.' || relation.relname
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    UNION ALL SELECT routine.proowner, 'routine', namespace.nspname || '.' || routine.proname
      FROM pg_catalog.pg_proc AS routine
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
    UNION ALL SELECT type.typowner, 'type', namespace.nspname || '.' || type.typname
      FROM pg_catalog.pg_type AS type
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = type.typnamespace
    UNION ALL SELECT default_acl.defaclrole, 'default-acl', default_acl.oid::text
      FROM pg_catalog.pg_default_acl AS default_acl
), entry(identity) AS (
    SELECT 'role:' || role.rolname || ':'
           || CASE
                  WHEN role.rolname = 'tracebed_erasure_group' THEN role.rolcanlogin::text
                  WHEN (NOT role.rolcanlogin AND role.rolpassword IS NULL)
                    OR (role.rolcanlogin AND role.rolpassword LIKE 'SCRAM-SHA-256$%')
                  THEN 'publication-shape-valid'
                  ELSE 'publication-shape-invalid'
              END
           || ':' || role.rolsuper::text || ':' || role.rolcreatedb::text
           || ':' || role.rolcreaterole::text || ':' || role.rolinherit::text
           || ':' || role.rolbypassrls::text || ':' || role.rolreplication::text
           || ':' || role.rolconnlimit::text || ':' || (role.rolconfig IS NULL)::text
           || ':' || (role.rolvaliduntil IS NULL)::text
      FROM protected_role AS role
    UNION ALL
    SELECT 'membership:' || granted.rolname || ':' || member.rolname || ':'
           || membership.admin_option::text || ':' || membership.inherit_option::text
           || ':' || membership.set_option::text
      FROM pg_catalog.pg_auth_members AS membership
      JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
      JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
     WHERE membership.roleid IN (SELECT oid FROM protected_role)
        OR membership.member IN (SELECT oid FROM protected_role)
    UNION ALL
    SELECT 'setting:' || role.rolname || ':' || setting.setdatabase::text || ':'
           || COALESCE(array_to_string(setting.setconfig, ','), '')
      FROM pg_catalog.pg_db_role_setting AS setting
      JOIN protected_role AS role ON role.oid = setting.setrole
    UNION ALL
    SELECT 'ownership:' || role.rolname || ':' || ownership.class_name || ':' || ownership.object_name
      FROM ownership
      JOIN protected_role AS role ON role.oid = ownership.owner_oid
)
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('tracebed.erasure-deployment-role-control/v1', 'UTF8')
    || COALESCE(
        string_agg(
            public.erasure_deployment_frame(pg_catalog.convert_to(identity, 'UTF8')),
            ''::bytea ORDER BY identity
        ),
        ''::bytea
    )
)
  FROM entry
$$;

-- The fixed manifest is materialized only after every E4 definition and ACL
-- below exists.  Its actual-tuple function deliberately uses dynamic routine
-- lookup so it can be declared before those later reviewed definitions.

CREATE FUNCTION public.erasure_deployment_actual_tuples() RETURNS TABLE(tuple_name text, tuple_digest bytea)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    -- LOGIN and the SCRAM verifier are intentionally excluded: bootstrap
    -- publishes those after HBA attestation, while this receipt pins their
    -- immutable non-credential privilege surface.
    SELECT 'role:tracebed_erasure', sha256(convert_to(
        format('role:%s:%s:%s:%s:%s:%s:%s',
            CASE WHEN role.rolinherit THEN 'INHERIT' ELSE 'NOINHERIT' END,
            CASE WHEN role.rolsuper THEN 'SUPERUSER' ELSE 'NOSUPERUSER' END,
            CASE WHEN role.rolcreatedb THEN 'CREATEDB' ELSE 'NOCREATEDB' END,
            CASE WHEN role.rolcreaterole THEN 'CREATEROLE' ELSE 'NOCREATEROLE' END,
            CASE WHEN role.rolreplication THEN 'REPLICATION' ELSE 'NOREPLICATION' END,
            CASE WHEN role.rolbypassrls THEN 'BYPASSRLS' ELSE 'NOBYPASSRLS' END,
            role.rolconnlimit
        ), 'UTF8'))
      FROM pg_roles AS role
     WHERE role.rolname = 'tracebed_erasure'
    UNION ALL
    SELECT 'authority-acl-profile-e4', public.erasure_deployment_authority_acl_digest()
    UNION ALL
    SELECT 'authority-schema-profile-e4', public.erasure_deployment_authority_schema_digest()
    UNION ALL
    SELECT 'role-control-profile-e4', public.erasure_deployment_role_control_digest()
    UNION ALL
    SELECT 'membership:tracebed_erasure_group-to-tracebed_erasure', sha256(convert_to(
        format(
            'membership:admin=%s:inherit=%s:set=%s',
            CASE WHEN membership.admin_option THEN 'true' ELSE 'false' END,
            CASE WHEN membership.inherit_option THEN 'true' ELSE 'false' END,
            CASE WHEN membership.set_option THEN 'true' ELSE 'false' END
        ), 'UTF8'))
      FROM pg_auth_members AS membership
      JOIN pg_roles AS granted ON granted.oid = membership.roleid
      JOIN pg_roles AS member ON member.oid = membership.member
     WHERE granted.rolname = 'tracebed_erasure_group' AND member.rolname = 'tracebed_erasure'
    UNION ALL
    SELECT 'acl:database-connect:tracebed_erasure', sha256(convert_to(
        CASE WHEN has_database_privilege('tracebed_erasure', current_database(), 'CONNECT')
             THEN 'acl:database-connect:tracebed_erasure' ELSE 'missing' END,
        'UTF8'
    ))
    UNION ALL
    SELECT 'acl:schema-usage:tracebed_erasure', sha256(convert_to(
        CASE WHEN has_schema_privilege('tracebed_erasure', 'public', 'USAGE')
             THEN 'acl:schema-usage:tracebed_erasure' ELSE 'missing' END,
        'UTF8'
    ))
    UNION ALL
    SELECT 'state:erasure_deployment_state', sha256(convert_to(
        CASE WHEN (
            SELECT array_agg(
                attribute.attname || ':'
                || pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
                || ':' || attribute.attnotnull::text
                ORDER BY attribute.attnum
            )
              FROM pg_catalog.pg_attribute AS attribute
             WHERE attribute.attrelid = 'public.erasure_deployment_state'::regclass
               AND attribute.attnum > 0 AND NOT attribute.attisdropped
        ) IS NOT DISTINCT FROM ARRAY[
            'singleton:boolean:true', 'epoch:bigint:true',
            'staged_at:timestamp with time zone:true',
            'activated_at:timestamp with time zone:false',
            'first_executor_activity_at:timestamp with time zone:false',
            'rollback_quarantined_at:timestamp with time zone:false'
        ]::text[]
        AND (SELECT relrowsecurity AND relforcerowsecurity
               FROM pg_catalog.pg_class
              WHERE oid = 'public.erasure_deployment_state'::regclass)
        THEN 'state:erasure_deployment_state' ELSE 'missing' END,
        'UTF8'
    ))
    UNION ALL
    SELECT 'function:' || routine.tuple_suffix, sha256(convert_to(pg_catalog.pg_get_functiondef(
        pg_catalog.to_regprocedure(routine.signature)::oid
    ), 'UTF8'))
      FROM (VALUES
        ('erasure_deployment_frame(bytea)',
         'public.erasure_deployment_frame(bytea)'),
        ('erasure_deployment_manifest_digest()',
         'public.erasure_deployment_manifest_digest()'),
        ('erasure_deployment_authority_acl_digest()',
         'public.erasure_deployment_authority_acl_digest()'),
        ('erasure_deployment_authority_schema_digest()',
         'public.erasure_deployment_authority_schema_digest()'),
        ('erasure_deployment_role_control_digest()',
         'public.erasure_deployment_role_control_digest()'),
        ('erasure_deployment_epoch_receipt(bigint,bigint,bytea,bytea,timestamptz,name,name)',
         'public.erasure_deployment_epoch_receipt(bigint,bigint,bytea,bytea,timestamp with time zone,name,name)'),
        ('erasure_deployment_state_guard()',
         'public.erasure_deployment_state_guard()'),
        ('tracebed_mark_erasure_executor_activity()',
         'public.tracebed_mark_erasure_executor_activity()'),
        ('tracebed_mark_erasure_executor_activity_trigger()',
         'public.tracebed_mark_erasure_executor_activity_trigger()'),
        ('tracebed_insert_subject_key_v2(uuid,bytea,uuid,bytea)',
         'public.tracebed_insert_subject_key_v2(uuid,bytea,uuid,bytea)'),
        ('tracebed_erasure_run_subject_digests(uuid,uuid)',
         'public.tracebed_erasure_run_subject_digests(uuid,uuid)'),
        ('tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer)',
         'public.tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer)'),
        ('erasure_deployment_actual_tuples()',
         'public.erasure_deployment_actual_tuples()'),
        ('erasure_deployment_security_assert()',
         'public.erasure_deployment_security_assert()'),
        ('erasure_deployment_epoch_append_guard()',
         'public.erasure_deployment_epoch_append_guard()'),
        ('tracebed_erasure_prepublication_readiness()',
         'public.tracebed_erasure_prepublication_readiness()'),
        ('tracebed_erasure_admission_is_open()',
         'public.tracebed_erasure_admission_is_open()'),
        ('tracebed_erasure_readiness()',
         'public.tracebed_erasure_readiness()'),
        ('tracebed_open_authority_admission()',
         'public.tracebed_open_authority_admission()'),
        ('tracebed_runtime_prepublication_readiness()',
         'public.tracebed_runtime_prepublication_readiness()'),
        ('tracebed_runtime_readiness()',
         'public.tracebed_runtime_readiness()')
      ) AS routine(tuple_suffix, signature)
    UNION ALL
    SELECT 'trigger:' || expected_trigger.tgname, sha256(convert_to(format(
        'trigger:%s:%s:%s:%s:%s:%s:%s',
        trigger_row.tgname, relation_namespace.nspname, relation_row.relname,
        trigger_row.tgtype, trigger_row.tgenabled,
        function_namespace.nspname, function_row.proname
    ), 'UTF8'))
      FROM pg_catalog.pg_trigger AS trigger_row
      JOIN pg_catalog.pg_class AS relation_row ON relation_row.oid = trigger_row.tgrelid
      JOIN pg_catalog.pg_namespace AS relation_namespace ON relation_namespace.oid = relation_row.relnamespace
      JOIN pg_catalog.pg_proc AS function_row ON function_row.oid = trigger_row.tgfoid
      JOIN pg_catalog.pg_namespace AS function_namespace ON function_namespace.oid = function_row.pronamespace
      JOIN (VALUES
          ('erasure_deployment_state_immutable'),
          ('erasure_request_executor_activity'),
          ('erasure_deployment_epoch_append_only')
      ) AS expected_trigger(tgname) ON expected_trigger.tgname = trigger_row.tgname
    UNION ALL
    SELECT 'acl:erasure-readiness-execute', sha256(convert_to(
        CASE WHEN has_function_privilege(
                'tracebed_erasure_group',
                'public.tracebed_erasure_prepublication_readiness()', 'EXECUTE'
            )
            AND has_function_privilege(
                'tracebed_erasure_group',
                'public.tracebed_erasure_admission_is_open()', 'EXECUTE'
            )
            AND has_function_privilege(
                'tracebed_erasure_group',
                'public.tracebed_erasure_readiness()', 'EXECUTE'
            )
            AND NOT has_function_privilege(
                'tracebed_api_group',
                'public.tracebed_erasure_prepublication_readiness()', 'EXECUTE'
            )
            AND NOT has_function_privilege(
                'tracebed_worker_group',
                'public.tracebed_erasure_prepublication_readiness()', 'EXECUTE'
            )
        THEN 'acl:erasure-readiness-execute' ELSE 'missing' END,
        'UTF8'
    ))
    UNION ALL
    SELECT 'acl:erasure-run-digest-reader-execute', sha256(convert_to(
        CASE WHEN has_function_privilege(
                'tracebed_api_group',
                'public.tracebed_erasure_run_subject_digests(uuid,uuid)', 'EXECUTE'
            )
            AND has_function_privilege(
                'tracebed_worker_group',
                'public.tracebed_erasure_run_subject_digests(uuid,uuid)', 'EXECUTE'
            )
            AND NOT has_function_privilege(
                'tracebed_erasure_group',
                'public.tracebed_erasure_run_subject_digests(uuid,uuid)', 'EXECUTE'
            )
            AND has_function_privilege(
                'tracebed_worker_group',
                'public.tracebed_insert_subject_key_v2(uuid,bytea,uuid,bytea)', 'EXECUTE'
            )
            AND NOT has_function_privilege(
                'tracebed_api_group',
                'public.tracebed_insert_subject_key_v2(uuid,bytea,uuid,bytea)', 'EXECUTE'
            )
            AND NOT has_function_privilege(
                'tracebed_erasure_group',
                'public.tracebed_insert_subject_key_v2(uuid,bytea,uuid,bytea)', 'EXECUTE'
            )
        THEN 'acl:erasure-run-digest-reader-execute' ELSE 'missing' END,
        'UTF8'
    ))
$$;

CREATE FUNCTION public.erasure_deployment_security_assert() RETURNS bytea
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deployment public.erasure_deployment_epoch;
    current_manifest bytea;
BEGIN
    -- This E4 assertion invokes the c12 collectors directly, so take the
    -- complete parent set before any catalog access.  The order is identical
    -- to project partition DDL and each ``ONLY`` lock leaves tenant leaves
    -- untouched.
    LOCK TABLE ONLY public.memory_item IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.memory_link IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.derived_state IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.trace_index IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.trace_subject IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.subject_key IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.outcome_event IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.injection_log IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.retrieval_event IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.blackboard_entry IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.invalidation_event IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.spend_ledger IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.review_queue IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.memory_status_log IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.memory_q_update IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.trace_learning_job IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.run_owner IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.subject_fence IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.run_fence IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.erase_run_set IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.erase_mem_set IN ACCESS SHARE MODE;
    LOCK TABLE ONLY public.run_memory_binding IN ACCESS SHARE MODE;
    IF EXISTS (
        (SELECT tuple_name, tuple_digest FROM public.erasure_deployment_actual_tuples()
         EXCEPT SELECT tuple_name, tuple_digest FROM public.erasure_deployment_tuple)
        UNION ALL
        (SELECT tuple_name, tuple_digest FROM public.erasure_deployment_tuple
         EXCEPT SELECT tuple_name, tuple_digest FROM public.erasure_deployment_actual_tuples())
    ) OR (SELECT count(*) FROM public.erasure_deployment_tuple) <> 34 THEN
        RAISE EXCEPTION 'erasure deployment manifest drift' USING ERRCODE = '55000';
    END IF;
    current_manifest := public.erasure_deployment_manifest_digest();
    SELECT * INTO deployment FROM public.erasure_deployment_epoch;
    IF NOT FOUND OR (SELECT count(*) FROM public.erasure_deployment_epoch) <> 1
       OR deployment.profile <> 'deployment_0013'
       OR deployment.manifest_digest IS DISTINCT FROM current_manifest
       OR deployment.parent_authority_epoch IS DISTINCT FROM (
            SELECT epoch FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1
       )
       OR deployment.parent_authority_receipt IS DISTINCT FROM (
            SELECT receipt_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1
       )
       OR deployment.receipt_digest IS DISTINCT FROM public.erasure_deployment_epoch_receipt(
            deployment.epoch, deployment.parent_authority_epoch, deployment.parent_authority_receipt,
            deployment.manifest_digest, deployment.transitioned_at,
            deployment.actor_session_user, deployment.actor_current_user
       ) THEN
        RAISE EXCEPTION 'erasure deployment receipt drift' USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.erasure_deployment_state
         WHERE singleton AND epoch = deployment.epoch
    ) OR (SELECT count(*) FROM public.erasure_deployment_state) <> 1 THEN
        RAISE EXCEPTION 'erasure deployment state drift' USING ERRCODE = '55000';
    END IF;
    RETURN deployment.receipt_digest;
END
$$;

CREATE FUNCTION public.erasure_deployment_epoch_append_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'erasure deployment epochs are append-only' USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER erasure_deployment_epoch_append_only
    BEFORE UPDATE OR DELETE ON public.erasure_deployment_epoch
    FOR EACH ROW EXECUTE FUNCTION public.erasure_deployment_epoch_append_guard();

CREATE FUNCTION public.tracebed_erasure_prepublication_readiness() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    role_state record;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_erasure'
       OR NULLIF(current_setting('tracebed.project_id', true), '') IS NOT NULL THEN
        RAISE EXCEPTION 'erasure readiness denied' USING ERRCODE = '42501';
    END IF;
    SELECT role.oid AS role_oid, role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
           role.rolinherit, role.rolbypassrls, role.rolreplication, role.rolconnlimit,
           role.rolconfig, auth.rolpassword, auth.rolvaliduntil
      INTO role_state
      FROM pg_roles AS role JOIN pg_authid AS auth ON auth.oid = role.oid
     WHERE role.rolname = session_user;
    IF NOT FOUND OR NOT role_state.rolcanlogin OR role_state.rolsuper
       OR role_state.rolcreatedb OR role_state.rolcreaterole OR NOT role_state.rolinherit
       OR role_state.rolbypassrls OR role_state.rolreplication OR role_state.rolconnlimit <> -1
       OR role_state.rolconfig IS NOT NULL OR role_state.rolpassword IS NULL
       OR role_state.rolpassword NOT LIKE 'SCRAM-SHA-256$%' OR role_state.rolvaliduntil IS NOT NULL
       OR (SELECT count(*) FROM pg_auth_members WHERE member = role_state.role_oid) <> 1
       OR NOT EXISTS (
           SELECT 1 FROM pg_auth_members AS membership
            JOIN pg_roles AS granted ON granted.oid = membership.roleid
           WHERE membership.member = role_state.role_oid AND granted.rolname = 'tracebed_erasure_group'
             AND membership.admin_option IS FALSE AND membership.inherit_option IS TRUE
             AND membership.set_option IS FALSE
       ) OR NOT EXISTS (
           SELECT 1 FROM public.erasure_deployment_state
            WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
       ) THEN
        RAISE EXCEPTION 'erasure readiness denied' USING ERRCODE = '42501';
    END IF;
    -- c12 records erasure-login-absent; E4's authenticated parent receipt
    -- and fixed manifest are its successor attestation.
    PERFORM public.erasure_deployment_security_assert();
END
$$;

CREATE FUNCTION public.tracebed_erasure_admission_is_open() RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    opened boolean;
BEGIN
    PERFORM public.tracebed_erasure_prepublication_readiness();
    SELECT admissions_open INTO opened
      FROM public.authority_admission_state
     WHERE singleton
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'erasure readiness denied' USING ERRCODE = '42501';
    END IF;
    RETURN opened;
END
$$;

CREATE FUNCTION public.tracebed_erasure_readiness() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF public.tracebed_erasure_admission_is_open() IS NOT TRUE THEN
        RAISE EXCEPTION 'erasure readiness denied' USING ERRCODE = '42501';
    END IF;
END
$$;

-- The c11 owner transition is still the one physical admission mutation, but
-- its E4 replacement makes the new receipt an in-database prerequisite too.
CREATE OR REPLACE FUNCTION public.tracebed_open_authority_admission() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_owner' THEN
        RAISE EXCEPTION 'authority admission transition denied' USING ERRCODE = '42501';
    END IF;
    PERFORM public.erasure_deployment_security_assert();
    PERFORM 1 FROM public.erasure_deployment_state
     WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority admission open requires active erasure deployment'
            USING ERRCODE = '55000';
    END IF;
    PERFORM 1 FROM public.authority_cutover_state
     WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
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
END
$$;

-- Preserve c12's API/worker role checks exactly, then bind their readiness
-- to the authenticated E4 deployment receipt.  This makes c12's deliberate
-- ``erasure-login-absent`` tuple transition only as part of an epoch whose
-- receipt is validated on every fresh API/worker connection.
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
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user)) <> 1
       OR NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_auth_members AS membership
            JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
            JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
            WHERE granted.rolname = expected_group AND member.rolname = session_user
              AND membership.admin_option IS FALSE AND membership.inherit_option IS TRUE
              AND membership.set_option IS FALSE
       ) OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_db_role_setting AS setting
             WHERE setting.setrole = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user)
       ) OR NULLIF(pg_catalog.current_setting('tracebed.project_id', true), '') IS NOT NULL
       OR NOT EXISTS (
            SELECT 1 FROM public.authority_cutover_state
             WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
       ) OR NOT EXISTS (
            SELECT 1 FROM public.erasure_cutover_state
             WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
       ) THEN
        RAISE EXCEPTION 'runtime readiness denied' USING ERRCODE = '42501';
    END IF;
    PERFORM public.erasure_deployment_security_assert();
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_runtime_readiness() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.tracebed_runtime_prepublication_readiness();
    PERFORM 1 FROM public.authority_admission_state
     WHERE singleton AND admissions_open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runtime readiness denied' USING ERRCODE = '42501';
    END IF;
END;
$$;

REVOKE ALL ON TABLE public.erasure_deployment_tuple, public.erasure_deployment_epoch,
                    public.erasure_deployment_state FROM PUBLIC, tracebed_app,
                    tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
REVOKE ALL ON FUNCTION public.erasure_deployment_frame(bytea),
    public.erasure_deployment_manifest_digest(),
    public.erasure_deployment_epoch_receipt(bigint,bigint,bytea,bytea,timestamp with time zone,name,name),
    public.erasure_deployment_actual_tuples(), public.erasure_deployment_security_assert(),
    public.erasure_deployment_state_guard(), public.erasure_deployment_epoch_append_guard(),
    public.tracebed_mark_erasure_executor_activity(),
    public.tracebed_mark_erasure_executor_activity_trigger(),
    public.tracebed_erasure_run_subject_digests(uuid,uuid)
FROM PUBLIC, tracebed_app, tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
REVOKE ALL ON FUNCTION public.tracebed_erasure_prepublication_readiness(),
    public.tracebed_erasure_admission_is_open(), public.tracebed_erasure_readiness()
FROM PUBLIC, tracebed_app, tracebed_api_group, tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_prepublication_readiness(),
    public.tracebed_erasure_admission_is_open(), public.tracebed_erasure_readiness()
TO tracebed_erasure_group;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_run_subject_digests(uuid,uuid)
TO tracebed_api_group, tracebed_worker_group;

-- Materialize the complete reviewed E4 catalog only after all definitions,
-- triggers, role membership, state shape, and ACLs above are present.  The
-- receipt below is therefore a fixed, self-authenticating successor to c12.
INSERT INTO public.erasure_deployment_tuple(tuple_name, tuple_digest)
SELECT tuple_name, tuple_digest
  FROM public.erasure_deployment_actual_tuples();

DO $$
DECLARE
    parent_row public.authority_acl_epoch;
    manifest bytea;
    transitioned timestamptz := statement_timestamp();
    receipt bytea;
BEGIN
    SELECT * INTO parent_row FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1;
    IF parent_row.profile <> 'cutover_0012'::public.authority_acl_profile THEN
        RAISE EXCEPTION 'erasure deployment requires c12 as receipt parent' USING ERRCODE = '55000';
    END IF;
    manifest := public.erasure_deployment_manifest_digest();
    receipt := public.erasure_deployment_epoch_receipt(
        0, parent_row.epoch, parent_row.receipt_digest, manifest, transitioned,
        session_user, current_user
    );
    INSERT INTO public.erasure_deployment_epoch(
        epoch, profile, parent_authority_epoch, parent_authority_receipt,
        manifest_digest, receipt_digest, transitioned_at, actor_session_user, actor_current_user
    ) VALUES (
        0, 'deployment_0013', parent_row.epoch, parent_row.receipt_digest,
        manifest, receipt, transitioned, session_user, current_user
    );
    INSERT INTO public.erasure_deployment_state(singleton, epoch, staged_at)
    VALUES (true, 0, transitioned);
END
$$;

DO $$
BEGIN
    PERFORM public.erasure_deployment_security_assert();
END
$$;
