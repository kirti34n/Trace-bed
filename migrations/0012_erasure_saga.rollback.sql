-- depends: 0012_erasure_saga

DO $$
BEGIN
    IF current_setting('tracebed.atomic_migration_runner', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.ingress_quarantined', true) IS DISTINCT FROM 'on'
       OR current_setting('tracebed.cluster_scope', true) IS DISTINCT FROM 'dedicated'
       OR session_user IS DISTINCT FROM current_user
       OR NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user)
       OR current_setting('max_prepared_transactions')::integer <> 0
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_prepared_xacts)
       OR EXISTS (SELECT 1 FROM public.work_queue)
       OR EXISTS (SELECT 1 FROM public.trace_learning_job WHERE state = 'running')
       OR EXISTS (SELECT 1 FROM public.authority_admission_state WHERE singleton AND admissions_open)
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid <> pg_catalog.pg_backend_pid()
                    AND usename IN ('tracebed_app','tracebed_api','tracebed_worker'))
       OR NOT EXISTS (SELECT 1 FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1)
       OR NOT EXISTS (
           SELECT 1 FROM public.erasure_cutover_state
            WHERE singleton
              AND first_activity_at IS NULL
              AND (activated_at IS NULL OR rollback_quarantined_at IS NOT NULL)
       )
       OR EXISTS (SELECT 1 FROM public.erasure_request)
       OR EXISTS (SELECT 1 FROM public.erasure_step_receipt)
       OR EXISTS (SELECT 1 FROM public.erasure_external_work)
       OR EXISTS (SELECT 1 FROM public.erasure_store_checkpoint)
       OR EXISTS (SELECT 1 FROM public.erasure_execution_capability)
       OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_auth_members AS membership
             WHERE membership.roleid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'tracebed_erasure_group')
                OR membership.member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'tracebed_erasure_group')
       )
       OR EXISTS (SELECT 1 FROM public.erase_run_set) OR EXISTS (SELECT 1 FROM public.erase_mem_set)
       OR EXISTS (SELECT 1 FROM public.subject_fence WHERE state <> 'live' OR request_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM public.run_fence WHERE state <> 'live' OR request_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM public.principal_grant WHERE role = 'erasure_request')
       OR EXISTS (SELECT 1 FROM public.subject_key WHERE wrap_version = 2)
       OR EXISTS (SELECT 1 FROM public.trace_index WHERE 2 = ANY(envelope_versions)) THEN
        RAISE EXCEPTION 'erasure foundation rollback denied' USING ERRCODE = '55000';
    END IF;
END
$$;

SET LOCAL search_path = public, pg_catalog;

LOCK TABLE project, principal, agent_type, agent_registration, principal_grant,
           run_owner, work_queue, dead_letter, trace_index, trace_subject,
           subject_key, memory_item, memory_link, derived_state, outcome_event,
           injection_log, retrieval_event, blackboard_entry, invalidation_event,
           spend_ledger, review_queue, memory_status_log, memory_q_update,
           trace_learning_job, killswitch_state, authority_acl_epoch, authority_acl_profile_tuple,
           authority_cutover_state, authority_admission_state, erasure_cutover_state,
           erasure_request, erasure_step_receipt, subject_fence, run_fence,
           erase_run_set, erase_mem_set, run_memory_binding,
           erasure_late_bind_capability, erasure_snapshot_capability,
           erasure_external_work, erasure_store_checkpoint, erasure_execution_capability,
           _yoyo_migration
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1
    ) OR (SELECT profile FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1)
          IS DISTINCT FROM 'cutover_0012'::public.authority_acl_profile THEN
        RAISE EXCEPTION 'erasure foundation rollback requires cutover-0012 epoch' USING ERRCODE = '55000';
    END IF;
    -- Authenticate the complete c12 catalog before dropping even one guard.
    -- A stale receipt alone is not a rollback authorization: this catches an
    -- altered E1 function, ACL, parent/leaf, index, or profile definition
    -- while the source state is still intact.
    PERFORM public.authority_acl_security_assert('cutover_0012');
    PERFORM public.authority_schema_security_assert('cutover_0012');
    -- The tracked migration receipt is part of the authenticated source
    -- state. Authenticate the exact frozen 0001..0012 chain, its order,
    -- finite receipt times, and the absence of any additional row.
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
                (11, '0011_authority_cutover', '657a61cff328a14ee991d76f852d1e28af46b65fbe90f48e7338ec8caef8e271'),
                (12, '0012_erasure_saga', 'cc6543ec143f8d79a7a3eca8001feaf0e62b3f29b417f8b636fa74004154eae6')
        ), actual AS (
            SELECT row_number() OVER (ORDER BY applied_at_utc, migration_id, migration_hash) AS ordinal,
                   migration_id, migration_hash, applied_at_utc,
                   lag(applied_at_utc) OVER (ORDER BY applied_at_utc, migration_id, migration_hash) AS previous_at
              FROM public._yoyo_migration
        )
        SELECT 1 FROM expected FULL JOIN actual USING (ordinal)
         WHERE actual.migration_id IS DISTINCT FROM expected.migration_id
            OR actual.migration_hash IS DISTINCT FROM expected.migration_hash
            OR actual.applied_at_utc IS NULL OR NOT isfinite(actual.applied_at_utc)
            OR (actual.previous_at IS NOT NULL AND actual.applied_at_utc < actual.previous_at)
            OR expected.ordinal IS NOT NULL AND actual.ordinal IS NULL
    ) OR (SELECT count(*) FROM public._yoyo_migration) <> 12 THEN
        RAISE EXCEPTION 'erasure foundation rollback yoyo history mismatch' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.subject_key WHERE subject_tag IS NULL
               OR NOT public.tracebed_subject_tag_is_valid(subject_tag, true)
               OR subject_digest IS DISTINCT FROM public.tracebed_subject_digest(project_id, subject_tag))
       OR EXISTS (SELECT 1 FROM public.trace_subject WHERE subject_tag IS NULL
               OR NOT public.tracebed_subject_tag_is_valid(subject_tag, false)
               OR subject_digest IS DISTINCT FROM public.tracebed_subject_digest(project_id, subject_tag))
       OR EXISTS (
           -- c12's deterministic legacy binding baseline may refine a
           -- proposal/parser/distiller memory beyond its direct tag.  The
           -- exact receipt below authenticates the normalized relation; this
           -- correlated shape check also proves the stored union still comes
           -- from that direct tag plus its bound run unions, never a caller
           -- supplied digest array.
           SELECT 1
             FROM public.memory_item AS memory_row
            WHERE memory_row.subject_digests IS DISTINCT FROM (
                WITH candidates AS (
                    SELECT public.tracebed_subject_digest(
                               memory_row.project_id, memory_row.subject_tag
                           ) AS digest
                     WHERE memory_row.subject_tag IS NOT NULL
                    UNION
                    SELECT trace_binding.subject_digest
                      FROM public.run_memory_binding AS binding
                      JOIN public.trace_subject AS trace_binding
                        ON trace_binding.project_id = binding.project_id
                       AND trace_binding.run_id = binding.run_id
                     WHERE binding.project_id = memory_row.project_id
                       AND binding.memory_id = memory_row.id
                       AND trace_binding.subject_digest
                           <> public.tracebed_subject_digest(memory_row.project_id, '__project__')
                )
                SELECT COALESCE(
                    array_agg(digest ORDER BY digest),
                    ARRAY[public.tracebed_subject_digest(memory_row.project_id, '__project__')]::bytea[]
                )
                  FROM candidates
            )
       )
       OR EXISTS (SELECT 1 FROM public.outcome_event AS outcome_row
                   WHERE outcome_row.subject_digests IS DISTINCT FROM COALESCE((
                       SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
                         FROM public.trace_subject AS binding
                        WHERE binding.project_id = outcome_row.project_id
                          AND binding.run_id = outcome_row.run_id
                   ), ARRAY[public.tracebed_subject_digest(outcome_row.project_id, '__project__')]))
       OR EXISTS (SELECT 1 FROM public.invalidation_event
                   WHERE subject_digests IS DISTINCT FROM ARRAY[public.tracebed_subject_digest(project_id, '__project__')])
       OR EXISTS (
           SELECT 1 FROM public.trace_learning_job AS job
            WHERE subject_digests IS DISTINCT FROM COALESCE((
                SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
                  FROM public.trace_subject AS binding
                 WHERE binding.project_id = job.project_id AND binding.run_id = job.run_id
            ), ARRAY[public.tracebed_subject_digest(job.project_id, '__project__')])
       )
       OR EXISTS (SELECT 1 FROM public.trace_index WHERE envelope_versions IS DISTINCT FROM CASE
                    WHEN payload_ref IS NULL THEN '{}'::smallint[] ELSE ARRAY[1]::smallint[] END) THEN
        RAISE EXCEPTION 'erasure foundation rollback backfill mismatch' USING ERRCODE = '55000';
    END IF;
    -- Recompute the immutable K/T/M receipt from stored opaque values before
    -- changing identities.  This rejects a valid-looking row deletion,
    -- wrapped-key mutation, or changed legacy count that a superficial
    -- column backfill comparison would otherwise miss.
    IF EXISTS (
        WITH key_frames AS (
            SELECT project_id, subject_digest,
                   decode('4b', 'hex') || uuid_send(project_id) || subject_digest || uuid_send(key_id)
                   || int2send(wrap_version) || CASE WHEN destroyed_at IS NULL THEN decode('00', 'hex') ELSE decode('01', 'hex') END
                   || sha256(wrapped_kek) AS frame
              FROM public.subject_key
        ), trace_frames AS (
            SELECT project_id, run_id, subject_digest,
                   decode('54', 'hex') || uuid_send(project_id) || uuid_send(run_id) || subject_digest AS frame
              FROM public.trace_subject
        ), memory_frames AS (
            SELECT project_id, id, subject_digests,
                   decode('4d', 'hex') || uuid_send(project_id) || uuid_send(id)
                   || int2send(cardinality(subject_digests)::smallint)
                   || COALESCE((SELECT string_agg(digest, ''::bytea ORDER BY ordinality)
                                  FROM unnest(memory_item.subject_digests) WITH ORDINALITY AS item(digest, ordinality)), ''::bytea) AS frame
              FROM public.memory_item
        ), binding_frames AS (
            SELECT project_id, run_id, memory_id,
                   decode('42', 'hex') || uuid_send(project_id) || uuid_send(run_id) || uuid_send(memory_id) AS frame
              FROM public.run_memory_binding
        ), counts AS (
            SELECT (SELECT count(*) FROM key_frames) AS key_count,
                   (SELECT count(*) FROM trace_frames) AS trace_count,
                   (SELECT count(*) FROM memory_frames) AS memory_count,
                   (SELECT count(*) FROM binding_frames) AS binding_count
        ), actual AS (
            SELECT counts.key_count, counts.trace_count, counts.memory_count, counts.binding_count,
                   sha256(convert_to('tracebed.erasure-binding-backfill/v2', 'UTF8') || decode('00', 'hex')
                     || int8send(counts.key_count)
                     || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, subject_digest) FROM key_frames), ''::bytea)
                     || int8send(counts.trace_count)
                     || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, run_id, subject_digest) FROM trace_frames), ''::bytea)
                     || int8send(counts.memory_count)
                     || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, id) FROM memory_frames), ''::bytea)
                     || int8send(counts.binding_count)
                     || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, run_id, memory_id) FROM binding_frames), ''::bytea)
                   ) AS digest
              FROM counts
        )
        SELECT 1 FROM actual CROSS JOIN public.erasure_cutover_state AS state
         WHERE state.singleton AND (
                state.legacy_subject_key_rows IS DISTINCT FROM actual.key_count
             OR state.legacy_trace_subject_rows IS DISTINCT FROM actual.trace_count
             OR state.legacy_memory_item_rows IS DISTINCT FROM actual.memory_count
             OR state.legacy_run_memory_binding_rows IS DISTINCT FROM actual.binding_count
             OR state.binding_backfill_digest IS DISTINCT FROM actual.digest
         )
    ) THEN
        RAISE EXCEPTION 'erasure foundation rollback binding receipt mismatch' USING ERRCODE = '55000';
    END IF;
    -- Fence membership is itself a migration receipt.  Require exactly the
    -- deterministic union (including timestamps/state shape), not merely an
    -- absence of obviously non-live rows.
    IF EXISTS (
        WITH expected_subject AS (
            SELECT project_id, subject_digest FROM public.subject_key
            UNION SELECT project_id, subject_digest FROM public.trace_subject
            UNION SELECT project_id, digest FROM public.memory_item CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            -- During forward migration a legacy memory without a raw tag is
            -- first project-attributed and fenced, then an authoritative
            -- proposal/learning binding may refine its stored union to real
            -- run subjects.  Fences are monotone, so retain that deterministic
            -- migration-era sentinel in the preactivity rollback proof even
            -- though the refined memory array no longer contains it.
            UNION SELECT project_id, public.tracebed_subject_digest(project_id, '__project__')
              FROM public.memory_item WHERE subject_tag IS NULL
            UNION SELECT project_id, digest FROM public.run_owner CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.trace_index CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.outcome_event CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.trace_learning_job CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.injection_log CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.retrieval_event CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.blackboard_entry CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.invalidation_event CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.memory_link CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.derived_state CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.spend_ledger CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.review_queue CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.memory_status_log CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.memory_q_update CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
            UNION SELECT project_id, digest FROM public.killswitch_state CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
        ), actual_subject AS (
            SELECT project_id, subject_digest FROM public.subject_fence
             WHERE state = 'live' AND request_id IS NULL AND fenced_at IS NULL AND erased_at IS NULL
        ), expected_run AS (
            SELECT project_id, run_id FROM public.run_owner
            UNION SELECT project_id, run_id FROM public.trace_index
            UNION SELECT project_id, run_id FROM public.trace_subject
            UNION SELECT project_id, run_id FROM public.outcome_event
            UNION SELECT project_id, run_id FROM public.trace_learning_job
            UNION SELECT project_id, run_id FROM public.injection_log
            UNION SELECT project_id, run_id FROM public.retrieval_event
            UNION SELECT project_id, run_id FROM public.blackboard_entry
            UNION SELECT project_id, run_id FROM public.work_queue WHERE run_id IS NOT NULL
            UNION SELECT project_id, run_id FROM public.dead_letter WHERE run_id IS NOT NULL
        ), actual_run AS (
            SELECT project_id, run_id FROM public.run_fence
             WHERE state = 'live' AND request_id IS NULL AND fenced_at IS NULL AND erased_at IS NULL
        )
        SELECT 1
         WHERE EXISTS ((SELECT * FROM expected_subject EXCEPT SELECT * FROM actual_subject)
                       UNION ALL (SELECT * FROM actual_subject EXCEPT SELECT * FROM expected_subject))
            OR EXISTS ((SELECT * FROM expected_run EXCEPT SELECT * FROM actual_run)
                       UNION ALL (SELECT * FROM actual_run EXCEPT SELECT * FROM expected_run))
            OR EXISTS (SELECT 1 FROM public.subject_fence AS fence JOIN public.erasure_cutover_state AS state ON state.singleton
                        WHERE fence.first_seen_at IS DISTINCT FROM state.cutover_at)
            OR EXISTS (SELECT 1 FROM public.run_fence AS fence JOIN public.erasure_cutover_state AS state ON state.singleton
                        WHERE fence.first_seen_at IS DISTINCT FROM state.cutover_at)
    ) THEN
        RAISE EXCEPTION 'erasure foundation rollback fence membership mismatch' USING ERRCODE = '55000';
    END IF;
END
$$;

DROP TRIGGER subject_key_erasure_activity ON subject_key;
DROP TRIGGER trace_subject_erasure_activity ON trace_subject;
DROP TRIGGER memory_item_erasure_activity ON memory_item;
DROP TRIGGER outcome_event_erasure_activity ON outcome_event;
DROP TRIGGER invalidation_event_erasure_activity ON invalidation_event;
DROP TRIGGER trace_learning_job_erasure_activity ON trace_learning_job;
DROP TRIGGER trace_index_erasure_activity ON trace_index;
DROP TRIGGER run_owner_erasure_activity ON run_owner;
DROP TRIGGER work_queue_erasure_activity ON work_queue;
DROP TRIGGER dead_letter_erasure_activity ON dead_letter;
DROP TRIGGER memory_link_erasure_activity ON memory_link;
DROP TRIGGER derived_state_erasure_activity ON derived_state;
DROP TRIGGER injection_log_erasure_activity ON injection_log;
DROP TRIGGER retrieval_event_erasure_activity ON retrieval_event;
DROP TRIGGER blackboard_entry_erasure_activity ON blackboard_entry;
DROP TRIGGER spend_ledger_erasure_activity ON spend_ledger;
DROP TRIGGER review_queue_erasure_activity ON review_queue;
DROP TRIGGER memory_status_log_erasure_activity ON memory_status_log;
DROP TRIGGER memory_q_update_erasure_activity ON memory_q_update;
DROP TRIGGER killswitch_state_erasure_activity ON killswitch_state;
DROP TRIGGER project_config_erasure_activity ON project_config;
DROP TRIGGER agent_type_config_erasure_activity ON agent_type_config;
DROP TRIGGER erasure_request_activity ON erasure_request;
DROP TRIGGER erasure_step_receipt_activity ON erasure_step_receipt;
DROP TRIGGER subject_fence_erasure_activity ON subject_fence;
DROP TRIGGER run_fence_erasure_activity ON run_fence;
DROP TRIGGER erase_run_set_erasure_activity ON erase_run_set;
DROP TRIGGER erase_mem_set_erasure_activity ON erase_mem_set;
DROP TRIGGER run_memory_binding_erasure_activity ON run_memory_binding;
DROP TRIGGER erasure_request_transition_guard ON erasure_request;
DROP TRIGGER erasure_step_receipt_append_only_guard ON erasure_step_receipt;
DROP TRIGGER subject_fence_transition_guard ON subject_fence;
DROP TRIGGER run_fence_transition_guard ON run_fence;
DROP TRIGGER erase_run_set_append_only_guard ON erase_run_set;
DROP TRIGGER erase_mem_set_append_only_guard ON erase_mem_set;
DROP TRIGGER run_memory_binding_append_only_guard ON run_memory_binding;
DROP TRIGGER subject_key_lifecycle_guard ON subject_key;
DROP TRIGGER aa_run_owner_subject_attribution_guard ON run_owner;
DROP TRIGGER aa_trace_index_subject_attribution_guard ON trace_index;
DROP TRIGGER aa_work_queue_subject_attribution_guard ON work_queue;
DROP TRIGGER aa_dead_letter_subject_attribution_guard ON dead_letter;
DROP TRIGGER aa_outcome_event_subject_attribution_guard ON outcome_event;
DROP TRIGGER aa_trace_learning_job_subject_attribution_guard ON trace_learning_job;
DROP TRIGGER aa_injection_log_subject_attribution_guard ON injection_log;
DROP TRIGGER aa_retrieval_event_subject_attribution_guard ON retrieval_event;
DROP TRIGGER aa_blackboard_entry_subject_attribution_guard ON blackboard_entry;
DROP TRIGGER aa_review_queue_subject_attribution_guard ON review_queue;
DROP TRIGGER aa_memory_status_log_subject_attribution_guard ON memory_status_log;
DROP TRIGGER aa_memory_q_update_subject_attribution_guard ON memory_q_update;
DROP TRIGGER aa_memory_link_subject_attribution_guard ON memory_link;
DROP TRIGGER aa_memory_item_subject_attribution_guard ON memory_item;
DROP TRIGGER aa_derived_state_subject_attribution_guard ON derived_state;
DROP TRIGGER aa_invalidation_event_subject_attribution_guard ON invalidation_event;
DROP TRIGGER aa_spend_ledger_subject_attribution_guard ON spend_ledger;
DROP TRIGGER aa_killswitch_state_subject_attribution_guard ON killswitch_state;
DROP TRIGGER ab_run_owner_erasure_write_guard ON run_owner;
DROP TRIGGER ab_work_queue_erasure_write_guard ON work_queue;
DROP TRIGGER ab_dead_letter_erasure_write_guard ON dead_letter;
DROP TRIGGER ab_trace_index_erasure_write_guard ON trace_index;
DROP TRIGGER ab_trace_subject_erasure_write_guard ON trace_subject;
DROP TRIGGER ab_subject_key_erasure_write_guard ON subject_key;
DROP TRIGGER ab_memory_item_erasure_write_guard ON memory_item;
DROP TRIGGER ab_memory_link_erasure_write_guard ON memory_link;
DROP TRIGGER ab_derived_state_erasure_write_guard ON derived_state;
DROP TRIGGER ab_outcome_event_erasure_write_guard ON outcome_event;
DROP TRIGGER ab_injection_log_erasure_write_guard ON injection_log;
DROP TRIGGER ab_retrieval_event_erasure_write_guard ON retrieval_event;
DROP TRIGGER ab_blackboard_entry_erasure_write_guard ON blackboard_entry;
DROP TRIGGER ab_invalidation_event_erasure_write_guard ON invalidation_event;
DROP TRIGGER ab_spend_ledger_erasure_write_guard ON spend_ledger;
DROP TRIGGER ab_review_queue_erasure_write_guard ON review_queue;
DROP TRIGGER ab_memory_status_log_erasure_write_guard ON memory_status_log;
DROP TRIGGER ab_memory_q_update_erasure_write_guard ON memory_q_update;
DROP TRIGGER ab_trace_learning_job_erasure_write_guard ON trace_learning_job;
DROP TRIGGER ab_killswitch_state_erasure_write_guard ON killswitch_state;
DROP TRIGGER ab_project_config_erasure_write_guard ON project_config;
DROP TRIGGER ab_agent_type_config_erasure_write_guard ON agent_type_config;
DROP TRIGGER ab_run_memory_binding_erasure_write_guard ON run_memory_binding;

DROP POLICY work_queue_erasure_isolation ON work_queue;
ALTER TABLE work_queue NO FORCE ROW LEVEL SECURITY;
ALTER TABLE work_queue DISABLE ROW LEVEL SECURITY;
DROP POLICY dead_letter_erasure_isolation ON dead_letter;
ALTER TABLE dead_letter NO FORCE ROW LEVEL SECURITY;
ALTER TABLE dead_letter DISABLE ROW LEVEL SECURITY;
DROP POLICY killswitch_state_erasure_isolation ON killswitch_state;
ALTER TABLE killswitch_state NO FORCE ROW LEVEL SECURITY;
ALTER TABLE killswitch_state DISABLE ROW LEVEL SECURITY;

DO $$
DECLARE
    parent_name text;
    leaf_name text;
BEGIN
    FOREACH parent_name IN ARRAY ARRAY[
        'memory_item', 'memory_link', 'derived_state', 'trace_index',
        'trace_subject', 'subject_key', 'outcome_event', 'injection_log',
        'retrieval_event', 'blackboard_entry', 'invalidation_event', 'spend_ledger',
        'review_queue', 'memory_status_log', 'memory_q_update',
        'trace_learning_job', 'run_owner'
    ] LOOP
        EXECUTE format('DROP POLICY %I ON public.%I', parent_name || '_isolation', parent_name);
        EXECUTE format(
            'CREATE POLICY %I ON public.%I USING '
            || '(project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid)',
            parent_name || '_isolation', parent_name
        );
        FOR leaf_name IN
            SELECT child.relname
              FROM pg_catalog.pg_inherits AS inheritance
              JOIN pg_catalog.pg_class AS parent ON parent.oid = inheritance.inhparent
              JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
              JOIN pg_catalog.pg_namespace AS child_namespace ON child_namespace.oid = child.relnamespace
             WHERE parent.relnamespace = 'public'::regnamespace
               AND parent.relname = parent_name
               AND child_namespace.nspname = 'public'
        LOOP
            EXECUTE format('DROP POLICY %I ON public.%I', leaf_name || '_isolation', leaf_name);
            EXECUTE format(
                'CREATE POLICY %I ON public.%I USING '
                || '(project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid)',
                leaf_name || '_isolation', leaf_name
            );
        END LOOP;
    END LOOP;
END;
$$;

-- Restore the c11 queue and partition ACL topology exactly.  0012 revoked
-- the raw scheduler/admission and run-binding grants before publishing its
-- profiled functions; a legal preactivity rollback must not leave c11 with
-- those capabilities silently missing, including on already-provisioned
-- partition leaves.
GRANT SELECT, INSERT ON public.work_queue TO tracebed_api_group;
GRANT USAGE, SELECT ON SEQUENCE public.work_queue_id_seq TO tracebed_api_group;
GRANT SELECT, UPDATE, DELETE ON public.work_queue TO tracebed_worker_group;
GRANT SELECT, INSERT ON public.dead_letter TO tracebed_worker_group;
DO $$
DECLARE
    child record;
    api_grant text;
    worker_grant text;
BEGIN
    FOR child IN
        SELECT relation.relname AS parent_name, relation.relname AS leaf_name
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS relation_schema ON relation_schema.oid = relation.relnamespace
         WHERE relation.relname IN (
            'memory_item','memory_link','derived_state','trace_index','trace_subject','subject_key',
            'outcome_event','injection_log','retrieval_event','blackboard_entry','invalidation_event',
            'spend_ledger','review_queue','memory_status_log','memory_q_update','trace_learning_job','run_owner'
         ) AND relation_schema.nspname = 'public'
        UNION ALL
        SELECT parent.relname AS parent_name, leaf.relname AS leaf_name
          FROM pg_catalog.pg_inherits AS inheritance
          JOIN pg_catalog.pg_class AS leaf ON leaf.oid = inheritance.inhrelid
          JOIN pg_catalog.pg_class AS parent ON parent.oid = inheritance.inhparent
          JOIN pg_catalog.pg_namespace AS leaf_schema ON leaf_schema.oid = leaf.relnamespace
          JOIN pg_catalog.pg_namespace AS parent_schema ON parent_schema.oid = parent.relnamespace
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

ALTER TABLE principal_grant DROP CONSTRAINT principal_grant_role_ck;
ALTER TABLE principal_grant ADD CONSTRAINT principal_grant_role_ck
    CHECK (role IN ('admin', 'data', 'export', 'feedback'));

-- E3 is still pre-activity only at this point.  Tear down its capabilities,
-- receipts and private tables before removing the c12 request ledger they
-- reference; a live saga, tombstone, or any E3 work row was rejected by the
-- rollback preflight above.
DROP TRIGGER IF EXISTS aa_erasure_step_receipt_insert_guard ON erasure_step_receipt;
DROP TRIGGER IF EXISTS aa_e3_prepare_fenced_request ON erasure_request;
DROP TRIGGER IF EXISTS zz_e3_fence_receipt ON erasure_request;
DROP TRIGGER IF EXISTS aa_erasure_request_update_guard ON erasure_request;
DROP TRIGGER IF EXISTS erasure_verified_commit_guard ON erasure_request;
DROP TRIGGER IF EXISTS erasure_external_work_transition_guard ON erasure_external_work;
DROP TRIGGER IF EXISTS erasure_store_checkpoint_transition_guard ON erasure_store_checkpoint;
DROP TABLE erasure_external_work;
DROP TABLE erasure_store_checkpoint;
DROP TABLE erasure_execution_capability;

-- E3 replaced these authority-root guards with a capability branch.  A
-- legal pre-activity rollback must restore the byte-identical c11 bodies,
-- not merely drop the capability relation they happened to query.
CREATE OR REPLACE FUNCTION public.project_enforce_lifecycle() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'projects cannot be physically deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'active' OR NEW.deleted_at IS NOT NULL THEN
            RAISE EXCEPTION 'new projects must be active and not deleted' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.provisioning_key_hash IS DISTINCT FROM OLD.provisioning_key_hash
       OR NEW.provisioning_request_hash IS DISTINCT FROM OLD.provisioning_request_hash THEN
        RAISE EXCEPTION 'project identity and provisioning hashes are immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'deleted' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'deleted projects are immutable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.name IS DISTINCT FROM OLD.name OR NEW.retention_policy IS DISTINCT FROM OLD.retention_policy)
       AND NOT (OLD.status IN ('active', 'suspended') AND NEW.status IN ('active', 'suspended')) THEN
        RAISE EXCEPTION 'project metadata may only change while active or suspended'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status = OLD.status THEN
        IF NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
            RAISE EXCEPTION 'project deletion timestamp is lifecycle managed' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status IN ('active', 'suspended') AND NEW.status IN ('active', 'suspended') THEN
        IF NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
            RAISE EXCEPTION 'project deletion timestamp is lifecycle managed' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status IN ('active', 'suspended') AND NEW.status = 'deleting' THEN
        IF NEW.deleted_at IS NOT NULL THEN
            RAISE EXCEPTION 'deleting projects cannot set deleted_at' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.status = 'deleting' AND NEW.status = 'deleted' THEN
        NEW.deleted_at := statement_timestamp();
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'illegal project lifecycle transition' USING ERRCODE = '23514';
END;
$$;

CREATE OR REPLACE FUNCTION public.principal_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'principals cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'new principals cannot be pre-revoked' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.external_ref IS DISTINCT FROM OLD.external_ref
       OR NEW.key_hash IS DISTINCT FROM OLD.key_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'principal identity is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.revoked_at IS NOT DISTINCT FROM OLD.revoked_at THEN
        RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'principal revocation is one-way' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.agent_type_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'agent types cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF NEW.agent_type_id IS DISTINCT FROM OLD.agent_type_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'agent type identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP FUNCTION public.tracebed_erasure_request_status_by_actor(uuid, uuid);
DROP FUNCTION public.tracebed_erasure_inspect(uuid);
DROP FUNCTION public.tracebed_erasure_verify_and_complete(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_resume_blocked(uuid, text);
DROP FUNCTION public.tracebed_erasure_fail(uuid, uuid, integer, uuid, text, text, text, text, bigint, bytea);
DROP FUNCTION public.tracebed_erasure_close_external_step(uuid, uuid, integer, uuid, text, text, bigint, bigint, bytea, text);
DROP FUNCTION public.tracebed_erasure_mark_external_work(uuid, uuid, integer, uuid, text, uuid, bigint, bigint, bytea, text);
DROP FUNCTION public.tracebed_erasure_external_work_batch(uuid, uuid, integer, uuid, text, text, integer);
DROP FUNCTION public.tracebed_erasure_primary_batch(uuid, uuid, integer, uuid, text, integer);
DROP FUNCTION public.tracebed_erasure_primary_remaining(uuid, uuid);
DROP FUNCTION public.tracebed_erasure_prepare_primary(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_seal_trace_manifest(uuid, uuid, integer, uuid, text, bigint, bigint, bytea);
DROP FUNCTION public.tracebed_erasure_trace_manifest_digest_for_request(uuid, uuid);
DROP FUNCTION public.tracebed_erasure_trace_refs_batch(uuid, uuid, integer, uuid, text, bigint, uuid, text, integer);
DROP FUNCTION public.tracebed_erasure_crypto_step(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_release(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_renew(uuid, uuid, integer, uuid, text, integer);
DROP FUNCTION public.tracebed_erasure_claim_request(uuid, text, integer, text[]);
DROP FUNCTION public.tracebed_erasure_claim_next(text, integer, text[]);
DROP FUNCTION public.tracebed_erasure_claim_selected(uuid, text, integer, text[]);
DROP FUNCTION public.tracebed_erasure_tombstone_project(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_drop_project_partitions(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_lock_project(uuid);
DROP FUNCTION public.tracebed_erasure_refresh_late_closure(uuid, uuid, uuid[], uuid[]);
DROP FUNCTION public.tracebed_erasure_mint_request_capability(uuid, uuid, integer, uuid);
DROP FUNCTION public.tracebed_erasure_request_update_guard();
DROP FUNCTION public.tracebed_erasure_verified_must_complete();
DROP FUNCTION public.tracebed_erasure_checkpoint_guard();
DROP FUNCTION public.tracebed_erasure_work_transition_guard();
DROP FUNCTION public.tracebed_e3_fence_receipt();
DROP FUNCTION public.tracebed_e3_prepare_fenced_request();
DROP FUNCTION public.tracebed_erasure_receipt_insert_guard();
DROP FUNCTION public.tracebed_erasure_append_receipt(uuid, uuid, integer, uuid, text, text, text, bigint, bigint, bytea);
DROP FUNCTION public.tracebed_erasure_receipt_digest(uuid, uuid, bigint, integer, text, text, text, integer, bigint, bigint, bytea, bytea, timestamptz, timestamptz);
DROP FUNCTION public.tracebed_erasure_drop_capability(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_mint_capability(uuid, uuid, integer, uuid, text, text);
DROP FUNCTION public.tracebed_erasure_capable(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_assert_lease(uuid, uuid, integer, uuid, text);
DROP FUNCTION public.tracebed_erasure_assert_caller();
DROP FUNCTION public.tracebed_erasure_manifest_digest(text[]);
DROP FUNCTION public.tracebed_erasure_closure_digest(uuid, uuid, bigint);
DROP FUNCTION public.tracebed_erasure_frame(bytea);
DROP FUNCTION public.tracebed_erasure_manifest_is_valid(text[]);
DROP TABLE erasure_step_receipt;
DROP TABLE erasure_request;
DROP TABLE erasure_cutover_state;
DROP TABLE subject_fence CASCADE;
DROP TABLE run_fence CASCADE;
DROP TABLE erase_run_set CASCADE;
DROP TABLE erase_mem_set CASCADE;
DROP TABLE run_memory_binding CASCADE;
DROP TABLE erasure_late_bind_capability;
DROP TABLE erasure_snapshot_capability;

DROP FUNCTION public.tracebed_request_erasure(uuid, uuid, uuid, uuid, text, text);
DROP FUNCTION public.tracebed_erasure_request_status(uuid, uuid, uuid, uuid, uuid);
DROP FUNCTION public.tracebed_open_erasure_guarded_run(uuid, uuid, uuid, uuid, uuid, text);
DROP FUNCTION public.tracebed_bind_run_subject_tags(uuid, uuid, uuid, uuid, uuid, text, text[]);
DROP FUNCTION public.tracebed_bind_run_memory(uuid, uuid, uuid, bytea[]);
DROP FUNCTION public.tracebed_lock_run_subject_snapshot(uuid, uuid, bytea[]);
DROP FUNCTION public.tracebed_insert_subject_key_v2(uuid, bytea, uuid, bytea);
DROP FUNCTION public.tracebed_assert_erasure_write_allowed(uuid, uuid[], bytea[]);
DROP FUNCTION public.tracebed_runtime_project_readable(uuid);
DROP FUNCTION public.tracebed_runtime_subjects_visible(uuid, bytea[]);
DROP FUNCTION public.tracebed_runtime_run_visible(uuid, uuid);
DROP FUNCTION public.tracebed_runtime_memory_visible(uuid, uuid);
DROP FUNCTION public.tracebed_enqueue_authorized(uuid, uuid, uuid, uuid, text, text, uuid, jsonb, integer, integer, timestamptz, integer, integer, integer, boolean);
DROP FUNCTION public.tracebed_insert_authorized_invalidation(uuid, uuid, uuid, uuid, text, jsonb);
DROP FUNCTION public.tracebed_worker_queue_claim(text, interval, integer);
DROP FUNCTION public.tracebed_worker_queue_disposition(bigint, integer, timestamptz, text, interval, text);
DROP FUNCTION public.tracebed_worker_queue_metrics(text);
DROP FUNCTION public.tracebed_fence_enforce_transition();
DROP FUNCTION public.tracebed_erasure_set_append_only();
DROP FUNCTION public.tracebed_run_memory_binding_append_only();
DROP FUNCTION public.tracebed_erasure_project_is_quiesced(uuid);
DROP FUNCTION public.tracebed_runtime_erasure_read_allowed(uuid);
DROP FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP FUNCTION public.tracebed_run_subject_attribution_guard();
DROP FUNCTION public.tracebed_memory_subject_attribution_guard();
DROP FUNCTION public.tracebed_memory_link_subject_attribution_guard();
DROP FUNCTION public.tracebed_memory_item_subject_attribution_guard();
DROP FUNCTION public.tracebed_project_subject_attribution_guard();

-- Restore c11 immutable bodies before their E2-only attribution columns are
-- removed.  This also prevents a legal rollback from retaining an
-- attribution-only terminal mutation branch.
CREATE OR REPLACE FUNCTION public.run_owner_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'run owners cannot be deleted' USING ERRCODE = '23514';
    END IF;
    RAISE EXCEPTION 'run owners are immutable' USING ERRCODE = '23514';
END;
$$;

CREATE OR REPLACE FUNCTION public.trace_index_enforce_terminal_immutability() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.outcome_status IN ('ok', 'error', 'cancelled') THEN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'terminal trace index rows cannot be deleted'
                USING ERRCODE = '23514';
        END IF;
        RAISE EXCEPTION 'terminal trace index rows are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.run_owner_enforce_immutability(),
                       public.trace_index_enforce_terminal_immutability()
    FROM PUBLIC;

ALTER TABLE subject_key DROP CONSTRAINT subject_key_wrap_shape_ck;
ALTER TABLE subject_key DROP CONSTRAINT subject_key_tag_binding_ck;
ALTER TABLE subject_key DROP CONSTRAINT subject_key_wrap_version_ck;
ALTER TABLE subject_key DROP CONSTRAINT subject_key_digest_ck;
DROP INDEX subject_key_raw_tag_uq;
ALTER TABLE subject_key DROP CONSTRAINT subject_key_pkey;
ALTER TABLE subject_key ALTER COLUMN subject_tag SET NOT NULL;
ALTER TABLE subject_key ADD CONSTRAINT subject_key_pkey PRIMARY KEY (project_id, subject_tag);
ALTER TABLE subject_key DROP COLUMN wrap_version;
ALTER TABLE subject_key DROP COLUMN subject_digest;

ALTER TABLE trace_subject DROP CONSTRAINT trace_subject_tag_binding_ck;
ALTER TABLE trace_subject DROP CONSTRAINT trace_subject_digest_ck;
DROP INDEX trace_subject_raw_tag_uq;
ALTER TABLE trace_subject DROP CONSTRAINT trace_subject_pkey;
ALTER TABLE trace_subject ALTER COLUMN subject_tag SET NOT NULL;
ALTER TABLE trace_subject ADD CONSTRAINT trace_subject_pkey PRIMARY KEY (project_id, run_id, subject_tag);
ALTER TABLE trace_subject DROP COLUMN subject_digest;

-- Restore the c11 per-leaf raw-tag index that 0012 replaced with the opaque
-- digest/run key.  This is part of the authenticated c11 leaf shape.
DO $$
DECLARE
    project_value uuid;
    leaf_name text;
BEGIN
    FOR project_value IN
        SELECT project_id FROM project
         WHERE status IN ('active', 'suspended') AND deleted_at IS NULL
    LOOP
        leaf_name := 'trace_subject_p_' || replace(project_value::text, '-', '');
        EXECUTE format('CREATE INDEX %I ON public.%I (subject_tag)',
                       leaf_name || '_subject', leaf_name);
    END LOOP;
END;
$$;

ALTER TABLE memory_item DROP CONSTRAINT memory_item_subject_tag_digest_ck;
ALTER TABLE memory_item DROP CONSTRAINT memory_item_subject_digests_ck;
ALTER TABLE memory_item DROP COLUMN subject_digests;
ALTER TABLE outcome_event DROP CONSTRAINT outcome_event_subject_digests_ck;
ALTER TABLE outcome_event DROP COLUMN subject_digests;
ALTER TABLE invalidation_event DROP CONSTRAINT invalidation_event_subject_digests_ck;
ALTER TABLE invalidation_event DROP COLUMN subject_digests;
ALTER TABLE trace_learning_job DROP CONSTRAINT trace_learning_job_subject_digests_ck;
ALTER TABLE trace_learning_job DROP COLUMN subject_digests;
ALTER TABLE run_owner DROP CONSTRAINT run_owner_subject_digests_ck;
ALTER TABLE run_owner DROP COLUMN subject_digests;
ALTER TABLE trace_index DROP CONSTRAINT trace_index_subject_digests_ck;
ALTER TABLE trace_index DROP COLUMN subject_digests;
ALTER TABLE injection_log DROP CONSTRAINT injection_log_subject_digests_ck;
ALTER TABLE injection_log DROP COLUMN subject_digests;
ALTER TABLE retrieval_event DROP CONSTRAINT retrieval_event_subject_digests_ck;
ALTER TABLE retrieval_event DROP COLUMN subject_digests;
ALTER TABLE blackboard_entry DROP CONSTRAINT blackboard_entry_subject_digests_ck;
ALTER TABLE blackboard_entry DROP COLUMN subject_digests;
ALTER TABLE memory_link DROP CONSTRAINT memory_link_subject_digests_ck;
ALTER TABLE memory_link DROP COLUMN subject_digests;
ALTER TABLE review_queue DROP CONSTRAINT review_queue_subject_digests_ck;
ALTER TABLE review_queue DROP COLUMN subject_digests;
ALTER TABLE memory_status_log DROP CONSTRAINT memory_status_log_subject_digests_ck;
ALTER TABLE memory_status_log DROP COLUMN subject_digests;
ALTER TABLE memory_q_update DROP CONSTRAINT memory_q_update_subject_digests_ck;
ALTER TABLE memory_q_update DROP COLUMN subject_digests;
ALTER TABLE derived_state DROP CONSTRAINT derived_state_subject_digests_ck;
ALTER TABLE derived_state DROP COLUMN subject_digests;
ALTER TABLE spend_ledger DROP CONSTRAINT spend_ledger_subject_digests_ck;
ALTER TABLE spend_ledger DROP COLUMN subject_digests;
ALTER TABLE killswitch_state DROP CONSTRAINT killswitch_state_subject_digests_ck;
ALTER TABLE killswitch_state DROP COLUMN subject_digests;
ALTER TABLE trace_index DROP CONSTRAINT trace_index_envelope_versions_ck;
ALTER TABLE trace_index DROP COLUMN envelope_versions;

-- Restore the byte-exact c11 transition guard after the E2-only column is
-- gone.  The E2 attribution-only terminal branch must not survive a legal
-- preactivity rollback.
CREATE OR REPLACE FUNCTION public.trace_learning_job_enforce_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'trace learning jobs cannot be deleted'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending'
           OR NEW.attempts <> 0
           OR NEW.lease_token IS NOT NULL
           OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL
           OR NEW.first_started_at IS NOT NULL
           OR NEW.trace_digest IS NOT NULL
           OR NEW.result_digest IS NOT NULL
           OR cardinality(NEW.memory_ids) <> 0
           OR NEW.skip_code IS NOT NULL
           OR NEW.last_error_code IS NOT NULL
           OR NEW.finished_at IS NOT NULL THEN
            RAISE EXCEPTION 'trace learning job insert must be a pristine pending schedule row'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.pipeline IS DISTINCT FROM OLD.pipeline
       OR NEW.pipeline_version IS DISTINCT FROM OLD.pipeline_version
       OR NEW.schedule_source IS DISTINCT FROM OLD.schedule_source
       OR NEW.scheduled_at IS DISTINCT FROM OLD.scheduled_at
       OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
       OR NEW.trace_ended_at IS DISTINCT FROM OLD.trace_ended_at THEN
        RAISE EXCEPTION 'trace learning job identity/schedule fields are immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.trace_digest IS NOT NULL AND NEW.trace_digest IS DISTINCT FROM OLD.trace_digest THEN
        RAISE EXCEPTION 'trace learning job trace_digest is write-once'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.first_started_at IS NOT NULL
       AND NEW.first_started_at IS DISTINCT FROM OLD.first_started_at THEN
        RAISE EXCEPTION 'trace learning job first_started_at is write-once'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.attempts IS DISTINCT FROM OLD.attempts
       AND NOT (
            OLD.state IN ('pending', 'retry')
            AND NEW.state = 'running'
            AND NEW.attempts = OLD.attempts + 1
       ) THEN
        RAISE EXCEPTION 'trace learning job attempts advance only on claim'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state IN ('succeeded', 'skipped', 'dead') THEN
        RAISE EXCEPTION 'terminal trace learning job is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.state IS DISTINCT FROM OLD.state
       AND NOT (
            (OLD.state = 'pending' AND NEW.state = 'running')
            OR (OLD.state = 'retry' AND NEW.state = 'running')
            OR (OLD.state = 'running' AND NEW.state IN ('retry', 'succeeded', 'skipped', 'dead'))
       ) THEN
        RAISE EXCEPTION 'illegal trace learning job state transition: % -> %', OLD.state, NEW.state
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP FUNCTION public.tracebed_mark_erasure_activity_trigger();
DROP FUNCTION public.tracebed_mark_erasure_activity();
DROP FUNCTION public.erasure_step_receipt_append_only();
DROP FUNCTION public.erasure_request_enforce_transition();
DROP FUNCTION public.subject_key_enforce_lifecycle();
DROP FUNCTION public.tracebed_lock_subject_bindings(uuid, bytea[]);
DROP FUNCTION public.tracebed_erasure_codes_are_valid(text[]);
DROP FUNCTION public.tracebed_envelope_versions_are_valid(smallint[]);
DROP FUNCTION public.tracebed_subject_digest(uuid, text);
DROP FUNCTION public.tracebed_subject_tag_is_valid(text, boolean);

-- Restore the exact cutover-0011 authority helper before its profile is
-- asserted.  In particular, the E1-only ``erasure_request`` vocabulary must
-- not survive a pre-activity rollback merely because the table constraint was
-- restored first.
CREATE OR REPLACE FUNCTION public.tracebed_require_active_grant(
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

-- Restore the exact c11 serving and closed-controller probes before the c11
-- profile assertion.  Their source body is intentionally byte-for-byte the
-- 0011 definition: an E1 rollback may not leave a readiness dependency on
-- the dropped erasure singleton.
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
       ) THEN
        RAISE EXCEPTION 'runtime readiness denied' USING ERRCODE = '42501';
    END IF;

    -- These owner-only assertions authenticate membership and every direct
    -- ACL/ownership tuple, not merely the handful checked above.
    PERFORM public.authority_acl_security_assert('cutover_0011');
    PERFORM public.authority_schema_security_assert('cutover_0011');
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

-- The c11 receipt is the final mutation; its exact helper body is restored by
-- the generated c11 profile on reapply rather than granting a new capability.
INSERT INTO public.authority_acl_epoch (
    epoch, profile, profile_version, source_acl_digest, result_acl_digest,
    source_schema_digest, result_schema_digest, yoyo_lock_repair
) SELECT
    (SELECT max(epoch) + 1 FROM public.authority_acl_epoch),
    'cutover_0011'::public.authority_acl_profile, 2,
    (SELECT result_acl_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
    public.authority_acl_security_assert('cutover_0011'::public.authority_acl_profile),
    (SELECT result_schema_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
    public.authority_schema_security_assert('cutover_0011'::public.authority_acl_profile),
    'not_required'::public.authority_yoyo_lock_repair;
