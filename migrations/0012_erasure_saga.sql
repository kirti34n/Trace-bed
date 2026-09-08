-- depends: 0011_authority_cutover

-- E1 is an unreleased foundation only.  It commits the opaque subject
-- bindings and the owner-only erasure ledger, but does not publish an
-- erasure login, HTTP operation, worker saga, or deployment route.

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
       OR (SELECT count(*) FROM public.authority_admission_state WHERE singleton) <> 1
       OR EXISTS (
           SELECT 1 FROM public.authority_admission_state
            WHERE singleton AND admissions_open
       )
       OR EXISTS (
           SELECT 1 FROM pg_catalog.pg_stat_activity
            WHERE pid <> pg_catalog.pg_backend_pid()
              AND usename IN ('tracebed_app', 'tracebed_api', 'tracebed_worker')
       )
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'tracebed_erasure')
       OR NOT EXISTS (
           SELECT 1 FROM public.authority_cutover_state
            WHERE singleton AND activated_at IS NOT NULL AND rollback_quarantined_at IS NULL
       )
       OR (SELECT count(*) FROM public._yoyo_migration) <> 11
       OR EXISTS (
           SELECT 1
             FROM (VALUES
                ('0001_registries', 'ca9fd297ce94f6dad44e14508a2d44f581a717e4387ec7ba32c38c1b67d6a2b4'),
                ('0002_partitioned', '22e2dc0758e77c7d1a28de420862111dc8a89da16305240bc2c7d53126e8eeb5'),
                ('0003_rls', '5181105981b30dbc0d9b20a8cedff308e51341d5bdd3501326468fcafd35320f'),
                ('0004_lifecycle', '332a0480e21dda2937e824595d1d570ccaa855848ee91a58cb47b8ecae513231'),
                ('0005_bm25', 'f710f686c18ac096cf1d749008c49e24ed08a36f8eb015fb3f70a5a162b90d45'),
                ('0006_q_update_ledger', '80d963725d38aa7e6e3618d918f9894fe52f5b9927bd1d937e0488f65e8c5551'),
                ('0007_project_provisioning', '3e4a20db26abaa4ebe83aa4ae2b3d20f3f412cb413db3062db54de019ab02eb1'),
                ('0008_trace_learning_job', '0c4d2368802cc954f4d160aa3a72b162bd36e068a8f2a663d47d2bf160e59e2f'),
                ('0009_trace_index_terminal_freeze', '796f7faa2c7e658d3e2948347db53a52a44ead0a97edd382ab55548a7216a722'),
                ('0010_authority_foundation', 'f33c0f4e096079c0c0c966b721ed8fb10389c9112766ec5398ab03611b4f319d'),
                ('0011_authority_cutover', '657a61cff328a14ee991d76f852d1e28af46b65fbe90f48e7338ec8caef8e271')
             ) AS expected(migration_id, migration_hash)
            WHERE NOT EXISTS (
                SELECT 1 FROM public._yoyo_migration AS actual
                 WHERE actual.migration_id = expected.migration_id
                   AND actual.migration_hash = expected.migration_hash
            )
       )
       OR (SELECT profile FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1)
              IS DISTINCT FROM 'cutover_0011'::public.authority_acl_profile THEN
        RAISE EXCEPTION 'erasure foundation preflight denied' USING ERRCODE = '55000';
    END IF;
END;
$$;

SET LOCAL search_path = public, pg_catalog;

LOCK TABLE project, principal, agent_type, agent_registration, principal_grant,
           run_owner, work_queue, dead_letter, trace_index, trace_subject,
           subject_key, memory_item, memory_link, derived_state, outcome_event,
           injection_log, retrieval_event, blackboard_entry, invalidation_event,
           spend_ledger, review_queue, memory_status_log, memory_q_update,
           trace_learning_job, killswitch_state, authority_acl_epoch, authority_acl_profile_tuple,
           authority_cutover_state, authority_admission_state, _yoyo_migration
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    PERFORM public.authority_acl_security_assert('cutover_0011');
    PERFORM public.authority_schema_security_assert('cutover_0011');
END;
$$;

CREATE FUNCTION public.tracebed_subject_tag_is_valid(subject_tag text, allow_reserved boolean)
RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    index_value integer;
    scalar_value text;
    code integer;
    whitespace_only boolean := true;
BEGIN
    IF char_length(subject_tag) NOT BETWEEN 1 AND 128
       OR octet_length(convert_to(subject_tag, 'UTF8')) NOT BETWEEN 1 AND 512
       OR (NOT allow_reserved AND subject_tag = '__project__') THEN
        RETURN false;
    END IF;
    FOR index_value IN 1..char_length(subject_tag) LOOP
        scalar_value := substr(subject_tag, index_value, 1);
        -- ``unicode(text)`` is not a PostgreSQL built-in.  Compare exact
        -- Unicode scalar characters so this remains byte-equivalent to the
        -- Python ingress validator on UTF-8 clusters without relying on a
        -- locale-sensitive regex character class.
        FOR code IN 1..31 LOOP
            IF scalar_value = chr(code) THEN
                RETURN false;
            END IF;
        END LOOP;
        FOR code IN 127..159 LOOP
            IF scalar_value = chr(code) THEN
                RETURN false;
            END IF;
        END LOOP;
        -- Python's ``str.isspace`` rejects a tag only when *all* of its
        -- scalars are whitespace.  In particular, ordinary internal spaces
        -- and NBSP are valid identity bytes and must not be normalised away.
        -- C0/C1 whitespace was already refused above as a control scalar.
        IF scalar_value <> ALL (ARRAY[
            chr(9), chr(10), chr(11), chr(12), chr(13), chr(28), chr(29),
            chr(30), chr(31), chr(32), chr(133), chr(160), chr(5760),
            chr(8192), chr(8193), chr(8194), chr(8195), chr(8196), chr(8197),
            chr(8198), chr(8199), chr(8200), chr(8201), chr(8202), chr(8232),
            chr(8233), chr(8239), chr(8287), chr(12288)
        ]) THEN
            whitespace_only := false;
        END IF;
    END LOOP;
    RETURN NOT whitespace_only;
END;
$$;

CREATE FUNCTION public.tracebed_subject_digest(project_id uuid, subject_tag text)
RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT sha256(
        convert_to('tracebed.subject-digest/v1', 'UTF8') || decode('00', 'hex')
        || uuid_send(project_id)
        || int4send(octet_length(convert_to(subject_tag, 'UTF8')))
        || convert_to(subject_tag, 'UTF8')
    )
$$;

CREATE FUNCTION public.tracebed_envelope_versions_are_valid(versions smallint[])
RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    ordered smallint[];
BEGIN
    IF versions IS NULL OR (cardinality(versions) <> 0 AND array_ndims(versions) IS DISTINCT FROM 1)
       OR cardinality(versions) > 2
       OR EXISTS (SELECT 1 FROM unnest(versions) AS value WHERE value IS NULL OR value NOT IN (1, 2)) THEN
        RETURN false;
    END IF;
    -- PostgreSQL's array_agg(empty) is NULL, whereas the E1 wire/database
    -- contract intentionally accepts the canonical one-dimensional empty
    -- array.  Handle it before comparing the sorted aggregate.
    IF cardinality(versions) = 0 THEN
        RETURN true;
    END IF;
    SELECT array_agg(value ORDER BY value) INTO ordered FROM unnest(versions) AS value;
    RETURN ordered IS NOT DISTINCT FROM versions
       AND cardinality(versions) = cardinality(ARRAY(SELECT DISTINCT value FROM unnest(versions) AS value));
END;
$$;

CREATE FUNCTION public.tracebed_erasure_codes_are_valid(codes text[])
RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    ordered text[];
BEGIN
    IF codes IS NULL OR (cardinality(codes) <> 0 AND array_ndims(codes) IS DISTINCT FROM 1) OR cardinality(codes) > 64
       OR EXISTS (SELECT 1 FROM unnest(codes) AS code WHERE code IS NULL OR code !~ '^[a-z][a-z0-9_]{0,63}$') THEN
        RETURN false;
    END IF;
    IF cardinality(codes) = 0 THEN
        RETURN true;
    END IF;
    -- Codes are a durable canonical byte sequence, not a database-locale
    -- ordering.  Keep the sort and duplicate decision explicitly C-collated.
    SELECT array_agg(code ORDER BY code COLLATE "C") INTO ordered FROM unnest(codes) AS code;
    RETURN ordered IS NOT DISTINCT FROM codes
       AND cardinality(codes) = cardinality(
           ARRAY(
               SELECT DISTINCT code COLLATE "C" AS canonical_code
                 FROM unnest(codes) AS code
                ORDER BY canonical_code
           )
       );
END;
$$;

-- Reject legacy values before any identity is changed.  A raw tag is never
-- normalised or repaired: a backfill either authenticates the exact binding
-- or leaves the database unchanged by aborting this transaction.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM subject_key
         WHERE NOT public.tracebed_subject_tag_is_valid(subject_tag, true)
    ) OR EXISTS (
        SELECT 1 FROM trace_subject
         WHERE NOT public.tracebed_subject_tag_is_valid(subject_tag, false)
    ) OR EXISTS (
        SELECT 1 FROM memory_item
         WHERE subject_tag IS NOT NULL
           AND NOT public.tracebed_subject_tag_is_valid(subject_tag, false)
    ) OR EXISTS (
        SELECT 1 FROM subject_key
         WHERE (destroyed_at IS NULL AND octet_length(wrapped_kek) <> 60)
            OR (destroyed_at IS NOT NULL AND octet_length(wrapped_kek) <> 0)
    ) THEN
        RAISE EXCEPTION 'erasure foundation refuses invalid legacy subject bindings'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

ALTER TABLE subject_key ADD COLUMN subject_digest bytea;
ALTER TABLE subject_key ADD COLUMN wrap_version smallint;
UPDATE subject_key
   SET subject_digest = public.tracebed_subject_digest(project_id, subject_tag),
       wrap_version = 1;
ALTER TABLE subject_key ALTER COLUMN subject_digest SET NOT NULL;
ALTER TABLE subject_key ALTER COLUMN wrap_version SET NOT NULL;
ALTER TABLE subject_key DROP CONSTRAINT subject_key_pkey;
ALTER TABLE subject_key ALTER COLUMN subject_tag DROP NOT NULL;
ALTER TABLE subject_key ADD CONSTRAINT subject_key_pkey PRIMARY KEY (project_id, subject_digest);
CREATE UNIQUE INDEX subject_key_raw_tag_uq ON subject_key (project_id, subject_tag)
    WHERE subject_tag IS NOT NULL;
ALTER TABLE subject_key ADD CONSTRAINT subject_key_digest_ck CHECK (octet_length(subject_digest) = 32);
ALTER TABLE subject_key ADD CONSTRAINT subject_key_wrap_version_ck CHECK (wrap_version IN (1, 2));
ALTER TABLE subject_key ADD CONSTRAINT subject_key_tag_binding_ck CHECK (
    subject_tag IS NULL OR (
        public.tracebed_subject_tag_is_valid(subject_tag, true)
        AND public.tracebed_subject_digest(project_id, subject_tag) = subject_digest
    )
);
ALTER TABLE subject_key ADD CONSTRAINT subject_key_wrap_shape_ck CHECK (
    (destroyed_at IS NULL AND octet_length(wrapped_kek) = 60
       AND ((wrap_version = 1 AND subject_tag IS NOT NULL) OR wrap_version = 2))
    OR (destroyed_at IS NOT NULL AND isfinite(destroyed_at) AND destroyed_at >= created_at
        AND wrapped_kek = ''::bytea)
);

CREATE FUNCTION public.subject_key_enforce_lifecycle() RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'subject key deletion denied' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.destroyed_at IS NOT NULL OR octet_length(NEW.wrapped_kek) <> 60 THEN
            RAISE EXCEPTION 'new subject key must be live' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.subject_digest IS DISTINCT FROM OLD.subject_digest
       OR NEW.subject_tag IS DISTINCT FROM OLD.subject_tag
       OR NEW.key_id IS DISTINCT FROM OLD.key_id
       OR NEW.wrap_version IS DISTINCT FROM OLD.wrap_version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'subject key identity is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF OLD.destroyed_at IS NOT NULL
       OR NEW.destroyed_at IS NULL OR NOT isfinite(NEW.destroyed_at)
       OR NEW.destroyed_at < OLD.created_at
       OR NEW.wrapped_kek <> ''::bytea THEN
        RAISE EXCEPTION 'subject key lifecycle denied' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS subject_key_lifecycle_guard ON subject_key;
CREATE TRIGGER subject_key_lifecycle_guard
    BEFORE INSERT OR UPDATE OR DELETE ON subject_key FOR EACH ROW EXECUTE FUNCTION public.subject_key_enforce_lifecycle();

-- Build every new per-leaf attribution index *before* changing a populated
-- leaf.  PostgreSQL marks an index built over a HOT-update chain with
-- ``indcheckxmin``; that state is transiently valid but is deliberately not
-- part of the c12 authenticated schema shape.  Building before each table's
-- backfill keeps an upgrade with real c11 rows byte-identical to a clean c12
-- install.  These two migration-only helpers are dropped before c12 is
-- receipted and are not a runtime surface.
CREATE FUNCTION public.tracebed_c12_build_leaf_subject_index(parent_name text)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    child_name text;
BEGIN
    IF parent_name NOT IN (
        'memory_item', 'outcome_event', 'invalidation_event', 'trace_learning_job',
        'run_owner', 'trace_index', 'injection_log', 'retrieval_event',
        'blackboard_entry', 'memory_link', 'derived_state', 'spend_ledger',
        'review_queue', 'memory_status_log', 'memory_q_update', 'killswitch_state'
    ) THEN
        RAISE EXCEPTION 'invalid c12 attribution index parent' USING ERRCODE = '22023';
    END IF;
    FOR child_name IN
        SELECT child.relname
          FROM pg_catalog.pg_inherits AS inheritance
          JOIN pg_catalog.pg_class AS parent ON parent.oid = inheritance.inhparent
          JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = child.relnamespace
         WHERE parent.relnamespace = 'public'::pg_catalog.regnamespace
           AND parent.relname = parent_name
           AND namespace.nspname = 'public'
    LOOP
        EXECUTE pg_catalog.format(
            'CREATE INDEX %I ON public.%I USING gin (subject_digests)',
            child_name || '_subjects', child_name
        );
    END LOOP;
END;
$$;

CREATE FUNCTION public.tracebed_c12_rebuild_trace_subject_index()
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    child_name text;
BEGIN
    FOR child_name IN
        SELECT child.relname
          FROM pg_catalog.pg_inherits AS inheritance
          JOIN pg_catalog.pg_class AS parent ON parent.oid = inheritance.inhparent
          JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = child.relnamespace
         WHERE parent.relnamespace = 'public'::pg_catalog.regnamespace
           AND parent.relname = 'trace_subject'
           AND namespace.nspname = 'public'
    LOOP
        EXECUTE pg_catalog.format('DROP INDEX public.%I', child_name || '_subject');
        EXECUTE pg_catalog.format(
            'CREATE INDEX %I ON public.%I (subject_digest, run_id)',
            child_name || '_subject', child_name
        );
    END LOOP;
END;
$$;

ALTER TABLE trace_subject ADD COLUMN subject_digest bytea;
SELECT public.tracebed_c12_rebuild_trace_subject_index();
UPDATE trace_subject
   SET subject_digest = public.tracebed_subject_digest(project_id, subject_tag);
ALTER TABLE trace_subject ALTER COLUMN subject_digest SET NOT NULL;
ALTER TABLE trace_subject DROP CONSTRAINT trace_subject_pkey;
ALTER TABLE trace_subject ALTER COLUMN subject_tag DROP NOT NULL;
ALTER TABLE trace_subject ADD CONSTRAINT trace_subject_pkey PRIMARY KEY (project_id, run_id, subject_digest);
CREATE UNIQUE INDEX trace_subject_raw_tag_uq ON trace_subject (project_id, run_id, subject_tag)
    WHERE subject_tag IS NOT NULL;
ALTER TABLE trace_subject ADD CONSTRAINT trace_subject_digest_ck CHECK (octet_length(subject_digest) = 32);
ALTER TABLE trace_subject ADD CONSTRAINT trace_subject_tag_binding_ck CHECK (
    subject_tag IS NULL OR (
        public.tracebed_subject_tag_is_valid(subject_tag, false)
        AND public.tracebed_subject_digest(project_id, subject_tag) = subject_digest
    )
);

-- A missing binding is explicitly project-attributed.  Empty remains a
-- positive assertion that a writer has no declared subject content; it is
-- never used as an "unknown" escape hatch.
ALTER TABLE memory_item ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('memory_item');
UPDATE memory_item
   SET subject_digests = CASE WHEN subject_tag IS NULL THEN ARRAY[public.tracebed_subject_digest(project_id, '__project__')]
                              ELSE ARRAY[public.tracebed_subject_digest(project_id, subject_tag)] END;
ALTER TABLE memory_item ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE memory_item ADD CONSTRAINT memory_item_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));
ALTER TABLE memory_item ADD CONSTRAINT memory_item_subject_tag_digest_ck CHECK (
    subject_tag IS NULL OR public.tracebed_subject_digest(project_id, subject_tag) = ANY(subject_digests)
);

ALTER TABLE outcome_event ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('outcome_event');
UPDATE outcome_event AS outcome_row
   SET subject_digests = COALESCE((
       SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
         FROM trace_subject AS binding
        WHERE binding.project_id = outcome_row.project_id
          AND binding.run_id = outcome_row.run_id
   ), ARRAY[public.tracebed_subject_digest(outcome_row.project_id, '__project__')]);
ALTER TABLE outcome_event ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE outcome_event ADD CONSTRAINT outcome_event_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));
ALTER TABLE invalidation_event ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('invalidation_event');
UPDATE invalidation_event
   SET subject_digests = ARRAY[public.tracebed_subject_digest(project_id, '__project__')];
ALTER TABLE invalidation_event ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE invalidation_event ADD CONSTRAINT invalidation_event_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));
ALTER TABLE trace_learning_job ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('trace_learning_job');
ALTER TABLE trace_learning_job DISABLE TRIGGER trace_learning_job_transition_guard;
UPDATE trace_learning_job AS job
   SET subject_digests = COALESCE((
      SELECT array_agg(subject_digest ORDER BY subject_digest) AS subject_digests
        FROM trace_subject
       WHERE trace_subject.project_id = job.project_id
         AND trace_subject.run_id = job.run_id
  ), ARRAY[public.tracebed_subject_digest(job.project_id, '__project__')]);
ALTER TABLE trace_learning_job ENABLE TRIGGER trace_learning_job_transition_guard;
ALTER TABLE trace_learning_job ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE trace_learning_job ADD CONSTRAINT trace_learning_job_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

-- Every disclosure/mutation family has durable, canonical attribution by
-- the time c12 is activated.  Run keyed rows derive the complete run union;
-- memory keyed rows derive the memory union; genuinely project-wide state is
-- explicitly tagged with the internal reserved project digest.  This keeps
-- an empty array meaningful (known no subject content) instead of using it
-- as an untracked/unknown sentinel.
ALTER TABLE run_owner ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('run_owner');
ALTER TABLE run_owner DISABLE TRIGGER run_owner_immutability_guard;
UPDATE run_owner AS owner_row
   SET subject_digests = COALESCE((
       SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
         FROM trace_subject AS binding
        WHERE binding.project_id = owner_row.project_id
          AND binding.run_id = owner_row.run_id
   ), ARRAY[public.tracebed_subject_digest(owner_row.project_id, '__project__')]);
ALTER TABLE run_owner ENABLE TRIGGER run_owner_immutability_guard;
ALTER TABLE run_owner ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE run_owner ADD CONSTRAINT run_owner_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE trace_index ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('trace_index');
ALTER TABLE trace_index DISABLE TRIGGER trace_index_terminal_immutability_guard;
UPDATE trace_index AS index_row
   SET subject_digests = COALESCE((
       SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
         FROM trace_subject AS binding
        WHERE binding.project_id = index_row.project_id
          AND binding.run_id = index_row.run_id
   ), ARRAY[public.tracebed_subject_digest(index_row.project_id, '__project__')]);
ALTER TABLE trace_index ENABLE TRIGGER trace_index_terminal_immutability_guard;
ALTER TABLE trace_index ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE trace_index ADD CONSTRAINT trace_index_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE injection_log ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('injection_log');
UPDATE injection_log AS log_row
   SET subject_digests = COALESCE((
       SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
         FROM trace_subject AS binding
        WHERE binding.project_id = log_row.project_id
          AND binding.run_id = log_row.run_id
   ), ARRAY[public.tracebed_subject_digest(log_row.project_id, '__project__')]);
ALTER TABLE injection_log ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE injection_log ADD CONSTRAINT injection_log_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE retrieval_event ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('retrieval_event');
UPDATE retrieval_event AS event_row
   SET subject_digests = COALESCE((
       SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
         FROM trace_subject AS binding
        WHERE binding.project_id = event_row.project_id
          AND binding.run_id = event_row.run_id
   ), ARRAY[public.tracebed_subject_digest(event_row.project_id, '__project__')]);
ALTER TABLE retrieval_event ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE retrieval_event ADD CONSTRAINT retrieval_event_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE blackboard_entry ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('blackboard_entry');
UPDATE blackboard_entry AS entry_row
   SET subject_digests = COALESCE((
       SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
         FROM trace_subject AS binding
        WHERE binding.project_id = entry_row.project_id
          AND binding.run_id = entry_row.run_id
   ), ARRAY[public.tracebed_subject_digest(entry_row.project_id, '__project__')]);
ALTER TABLE blackboard_entry ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE blackboard_entry ADD CONSTRAINT blackboard_entry_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE memory_link ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('memory_link');
UPDATE memory_link AS link_row
   SET subject_digests = CASE
       WHEN EXISTS (
           SELECT 1 FROM memory_item AS memory_row
            WHERE memory_row.project_id = link_row.project_id
              AND memory_row.id IN (link_row.src_id, link_row.dst_id)
       ) THEN COALESCE((
           SELECT array_agg(DISTINCT digest ORDER BY digest)
             FROM memory_item AS memory_row
             CROSS JOIN LATERAL unnest(memory_row.subject_digests) AS item(digest)
            WHERE memory_row.project_id = link_row.project_id
              AND memory_row.id IN (link_row.src_id, link_row.dst_id)
       ), '{}'::bytea[])
       ELSE ARRAY[public.tracebed_subject_digest(link_row.project_id, '__project__')]
   END;
ALTER TABLE memory_link ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE memory_link ADD CONSTRAINT memory_link_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE review_queue ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('review_queue');
UPDATE review_queue AS queue_row
   SET subject_digests = CASE
       WHEN queue_row.memory_id IS NULL THEN ARRAY[public.tracebed_subject_digest(queue_row.project_id, '__project__')]
       ELSE COALESCE((
           SELECT memory_row.subject_digests FROM memory_item AS memory_row
            WHERE memory_row.project_id = queue_row.project_id AND memory_row.id = queue_row.memory_id
       ), ARRAY[public.tracebed_subject_digest(queue_row.project_id, '__project__')])
   END;
ALTER TABLE review_queue ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE review_queue ADD CONSTRAINT review_queue_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE memory_status_log ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('memory_status_log');
UPDATE memory_status_log AS log_row
   SET subject_digests = COALESCE((
       SELECT memory_row.subject_digests FROM memory_item AS memory_row
        WHERE memory_row.project_id = log_row.project_id AND memory_row.id = log_row.memory_id
   ), ARRAY[public.tracebed_subject_digest(log_row.project_id, '__project__')]);
ALTER TABLE memory_status_log ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE memory_status_log ADD CONSTRAINT memory_status_log_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE memory_q_update ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('memory_q_update');
UPDATE memory_q_update AS update_row
   SET subject_digests = COALESCE((
       SELECT memory_row.subject_digests FROM memory_item AS memory_row
        WHERE memory_row.project_id = update_row.project_id AND memory_row.id = update_row.memory_id
   ), ARRAY[public.tracebed_subject_digest(update_row.project_id, '__project__')]);
ALTER TABLE memory_q_update ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE memory_q_update ADD CONSTRAINT memory_q_update_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE derived_state ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('derived_state');
UPDATE derived_state
   SET subject_digests = ARRAY[public.tracebed_subject_digest(project_id, '__project__')];
ALTER TABLE derived_state ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE derived_state ADD CONSTRAINT derived_state_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE spend_ledger ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('spend_ledger');
UPDATE spend_ledger
   SET subject_digests = ARRAY[public.tracebed_subject_digest(project_id, '__project__')];
ALTER TABLE spend_ledger ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE spend_ledger ADD CONSTRAINT spend_ledger_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

ALTER TABLE killswitch_state ADD COLUMN subject_digests bytea[];
SELECT public.tracebed_c12_build_leaf_subject_index('killswitch_state');
UPDATE killswitch_state
   SET subject_digests = ARRAY[public.tracebed_subject_digest(project_id, '__project__')];
ALTER TABLE killswitch_state ALTER COLUMN subject_digests SET NOT NULL;
ALTER TABLE killswitch_state ADD CONSTRAINT killswitch_state_subject_digests_ck
    CHECK (subject_digests_are_valid(subject_digests));

-- The migration-only pre-backfill index helpers must not survive into the
-- authenticated c12 function surface.
DROP FUNCTION public.tracebed_c12_rebuild_trace_subject_index();
DROP FUNCTION public.tracebed_c12_build_leaf_subject_index(text);

-- Parent indexes are deliberately not created here: per-project child names
-- are part of the authenticated DDL profile.  The leaf loop below only
-- verifies that the pre-backfill indexes use the same vocabulary late
-- provisioning emits; it must not rebuild populated leaves.
ALTER TABLE trace_index ADD COLUMN envelope_versions smallint[] NOT NULL DEFAULT '{}'::smallint[];
UPDATE trace_index SET envelope_versions = CASE WHEN payload_ref IS NULL THEN '{}'::smallint[] ELSE ARRAY[1]::smallint[] END;
ALTER TABLE trace_index ALTER COLUMN envelope_versions DROP DEFAULT;
ALTER TABLE trace_index ADD CONSTRAINT trace_index_envelope_versions_ck
    CHECK (public.tracebed_envelope_versions_are_valid(envelope_versions));

-- The original job ledger freezes terminal rows.  E2 permits exactly one
-- server-authenticated attribution extension: no lifecycle/receipt field may
-- move, old attribution is retained, and the new array is exactly the
-- authoritative run union.  Direct API/worker UPDATE cannot satisfy the
-- ``current_user`` condition because only the profiled SECURITY DEFINER bind
-- routine runs as ``tracebed_owner``.
CREATE OR REPLACE FUNCTION public.trace_learning_job_enforce_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (
            SELECT 1 FROM public.erasure_execution_capability AS capability
             WHERE capability.backend_pid = pg_backend_pid()
               AND capability.transaction_id = txid_current()
               AND capability.project_id = OLD.project_id
               AND capability.operation = 'primary_purge'
        ) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'trace learning jobs cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.attempts <> 0
           OR NEW.lease_token IS NOT NULL OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL OR NEW.first_started_at IS NOT NULL
           OR NEW.trace_digest IS NOT NULL OR NEW.result_digest IS NOT NULL
           OR cardinality(NEW.memory_ids) <> 0 OR NEW.skip_code IS NOT NULL
           OR NEW.last_error_code IS NOT NULL OR NEW.finished_at IS NOT NULL THEN
            RAISE EXCEPTION 'trace learning job insert must be a pristine pending schedule row'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state IN ('succeeded', 'skipped', 'dead') THEN
        IF session_user = 'tracebed_api'
           AND current_user = 'tracebed_owner'
           AND pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
           AND (pg_catalog.to_jsonb(NEW) - 'subject_digests')
                 IS NOT DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'subject_digests')
           -- An initial project sentinel means "positively unbound", not a
           -- subject identity.  The authoritative binder may refine exactly
           -- that one value to the first stable run union; every concrete
           -- subject attribution remains monotone.
           AND (
               OLD.subject_digests <@ NEW.subject_digests
               OR OLD.subject_digests IS NOT DISTINCT FROM ARRAY[
                   public.tracebed_subject_digest(NEW.project_id, '__project__')
               ]::bytea[]
           )
           AND NEW.subject_digests IS NOT DISTINCT FROM COALESCE((
               SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
                 FROM public.trace_subject AS binding
                WHERE binding.project_id = NEW.project_id AND binding.run_id = NEW.run_id
           ), ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')]) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'terminal trace learning job is immutable' USING ERRCODE = '23514';
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
        RAISE EXCEPTION 'trace learning job trace_digest is write-once' USING ERRCODE = '23514';
    END IF;
    IF OLD.first_started_at IS NOT NULL AND NEW.first_started_at IS DISTINCT FROM OLD.first_started_at THEN
        RAISE EXCEPTION 'trace learning job first_started_at is write-once' USING ERRCODE = '23514';
    END IF;
    IF NEW.attempts IS DISTINCT FROM OLD.attempts
       AND NOT (OLD.state IN ('pending', 'retry') AND NEW.state = 'running'
                AND NEW.attempts = OLD.attempts + 1) THEN
        RAISE EXCEPTION 'trace learning job attempts advance only on claim' USING ERRCODE = '23514';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NOT ((OLD.state = 'pending' AND NEW.state = 'running')
                OR (OLD.state = 'retry' AND NEW.state = 'running')
                OR (OLD.state = 'running' AND NEW.state IN ('retry', 'succeeded', 'skipped', 'dead'))) THEN
        RAISE EXCEPTION 'illegal trace learning job state transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- A terminal trace archive remains immutable except for the one
-- security-definer attribution extension made by the authoritative binder.
-- The attribution guard below runs first and replaces any caller-supplied
-- array with the current complete run union.
CREATE OR REPLACE FUNCTION public.trace_index_enforce_terminal_immutability() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.outcome_status IN ('ok', 'error', 'cancelled') THEN
            RAISE EXCEPTION 'terminal trace index rows cannot be deleted' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.outcome_status IN ('ok', 'error', 'cancelled') THEN
        IF session_user = 'tracebed_api'
           AND current_user = 'tracebed_owner'
           AND pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
           AND (pg_catalog.to_jsonb(NEW) - 'subject_digests')
                 IS NOT DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'subject_digests')
           -- See trace_learning_job_enforce_transition: only the internal
           -- project sentinel may be refined to a first run union.
           AND (
               OLD.subject_digests <@ NEW.subject_digests
               OR OLD.subject_digests IS NOT DISTINCT FROM ARRAY[
                   public.tracebed_subject_digest(NEW.project_id, '__project__')
               ]::bytea[]
           )
           AND NEW.subject_digests IS NOT DISTINCT FROM COALESCE((
               SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
                 FROM public.trace_subject AS binding
                WHERE binding.project_id = NEW.project_id AND binding.run_id = NEW.run_id
           ), ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')]) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'terminal trace index rows are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- ``run_owner`` is an immutable authority binding, with the same narrow
-- server-authenticated monotone attribution extension as terminal traces.
CREATE OR REPLACE FUNCTION public.run_owner_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'run owners cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF session_user = 'tracebed_api'
       AND current_user = 'tracebed_owner'
       AND pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       AND (pg_catalog.to_jsonb(NEW) - 'subject_digests')
             IS NOT DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'subject_digests')
       -- A new run is initially project-attributed until the authoritative
       -- binder observes its first tag.  That sentinel refinement is the
       -- only non-superset transition permitted here.
       AND (
           OLD.subject_digests <@ NEW.subject_digests
           OR OLD.subject_digests IS NOT DISTINCT FROM ARRAY[
               public.tracebed_subject_digest(NEW.project_id, '__project__')
           ]::bytea[]
       )
       AND NEW.subject_digests IS NOT DISTINCT FROM COALESCE((
           SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
             FROM public.trace_subject AS binding
            WHERE binding.project_id = NEW.project_id AND binding.run_id = NEW.run_id
       ), ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')]) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'run owners are immutable' USING ERRCODE = '23514';
END;
$$;

/* Deferred with the rest of the early E3 declarations until the original
 * c12 tables exist below.  The actual ACL application follows the final
 * E3 redefinitions at the end of this source. 
-- E3 is an EXECUTE-only deployment artifact.  It deliberately provisions no
-- login or membership; a later deployment gate may create a single direct
-- member of tracebed_erasure_group.  Keep every raw relation and helper out
-- of the API and ordinary worker identities.
REVOKE ALL ON public.erasure_external_work, public.erasure_store_checkpoint,
              public.erasure_execution_capability
    FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
         tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM tracebed_erasure_group;
REVOKE ALL ON FUNCTION public.tracebed_erasure_manifest_is_valid(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_frame(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_closure_digest(uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_manifest_digest(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_assert_caller() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_assert_lease(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_capable(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mint_capability(uuid,uuid,integer,uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_drop_capability(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_lock_project(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_drop_project_partitions(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_tombstone_project(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_receipt_digest(uuid,uuid,bigint,integer,text,text,text,integer,bigint,bigint,bytea,bytea,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_append_receipt(uuid,uuid,integer,uuid,text,text,text,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_selected(uuid,text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mint_request_capability(uuid,uuid,integer,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_refresh_late_closure(uuid,uuid,uuid[],uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_trace_manifest_digest_for_request(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_primary_remaining(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_next(text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_request(uuid,text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_renew(uuid,uuid,integer,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_crypto_step(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_trace_refs_batch(uuid,uuid,integer,uuid,text,bigint,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_seal_trace_manifest(uuid,uuid,integer,uuid,text,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_prepare_primary(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_external_work_batch(uuid,uuid,integer,uuid,text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mark_external_work(uuid,uuid,integer,uuid,text,uuid,bigint,bigint,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_close_external_step(uuid,uuid,integer,uuid,text,text,bigint,bigint,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_verify_and_complete(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_fail(uuid,uuid,integer,uuid,text,text,text,text,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_release(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_resume_blocked(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_inspect(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_request_status_by_actor(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_refresh_late_closure(uuid,uuid,uuid[],uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_claim_next(text,integer,text[]),
    public.tracebed_erasure_claim_request(uuid,text,integer,text[]),
    public.tracebed_erasure_renew(uuid,uuid,integer,uuid,text,integer),
    public.tracebed_erasure_crypto_step(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_trace_refs_batch(uuid,uuid,integer,uuid,text,bigint,uuid,text,integer),
    public.tracebed_erasure_seal_trace_manifest(uuid,uuid,integer,uuid,text,bigint,bigint,bytea),
    public.tracebed_erasure_prepare_primary(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer),
    public.tracebed_erasure_external_work_batch(uuid,uuid,integer,uuid,text,text,integer),
    public.tracebed_erasure_mark_external_work(uuid,uuid,integer,uuid,text,uuid,bigint,bigint,bytea,text),
    public.tracebed_erasure_close_external_step(uuid,uuid,integer,uuid,text,text,bigint,bigint,bytea,text),
    public.tracebed_erasure_verify_and_complete(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_fail(uuid,uuid,integer,uuid,text,text,text,text,bigint,bytea),
    public.tracebed_erasure_release(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_resume_blocked(uuid,text), public.tracebed_erasure_inspect(uuid)
TO tracebed_erasure_group;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_request_status_by_actor(uuid,uuid)
TO tracebed_api_group;
*/

CREATE OR REPLACE FUNCTION public.tracebed_erasure_external_work_batch(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, requested_store_code text, requested_limit integer
) RETURNS TABLE (work_id uuid, target_kind text, target_id uuid, work_revision bigint, attempt integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row record;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.phase NOT IN ('primary_purged','external_purged') OR requested_limit NOT BETWEEN 1 AND 10000
       OR requested_store_code <> ALL(request_row.store_manifest) THEN
        RAISE EXCEPTION 'erasure external work denied' USING ERRCODE = 'P0013';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'external_work'
    );
    RETURN QUERY
    WITH candidates AS (
        SELECT work.work_id FROM public.erasure_external_work AS work
         WHERE work.project_id = expected_project_id AND work.request_id = expected_request_id
           AND work.store_code = requested_store_code AND work.discovered_revision = request_row.closure_revision
           AND (work.state = 'pending' OR (work.state = 'in_progress' AND work.claimed_generation < expected_generation))
         ORDER BY work.work_id FOR UPDATE SKIP LOCKED LIMIT requested_limit
    ), claimed AS (
        UPDATE public.erasure_external_work AS work
           SET state = 'in_progress', claimed_generation = expected_generation,
               claimed_token = expected_lease_token, attempt = work.attempt + 1,
               started_at = statement_timestamp(), verified_at = NULL, affected_rows = NULL,
               last_result_code = NULL, postcondition_digest = NULL
          FROM candidates WHERE work.work_id = candidates.work_id
        RETURNING work.work_id, work.target_kind, work.target_id, work.discovered_revision, work.attempt
    ) SELECT * FROM claimed ORDER BY work_id;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'external_work');
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_mark_external_work(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, expected_work_id uuid,
    expected_work_revision bigint, expected_affected_rows bigint,
    expected_postcondition_digest bytea, expected_result_code text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row record;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF expected_work_id IS NULL OR expected_work_revision <> request_row.closure_revision
       OR expected_affected_rows < 0 OR octet_length(expected_postcondition_digest) <> 32
       OR expected_result_code NOT IN ('ok','already_absent','not_configured','embedded_primary') THEN
        RAISE EXCEPTION 'erasure external mark denied' USING ERRCODE = 'P0010';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'external_work'
    );
    UPDATE public.erasure_external_work
       SET state = 'verified', verified_at = statement_timestamp(), affected_rows = expected_affected_rows,
           last_result_code = expected_result_code, postcondition_digest = expected_postcondition_digest
     WHERE work_id = expected_work_id AND project_id = expected_project_id AND request_id = expected_request_id
       AND discovered_revision = expected_work_revision AND state = 'in_progress'
       AND claimed_generation = expected_generation AND claimed_token = expected_lease_token;
    IF NOT FOUND THEN RAISE EXCEPTION 'erasure lease lost' USING ERRCODE = 'P0011'; END IF;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'external_work');
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_close_external_step(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, requested_store_code text,
    supplied_target_count bigint, supplied_affected_rows bigint, supplied_postcondition_digest bytea,
    supplied_result_code text
) RETURNS TABLE (phase text, closure_revision bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row record; expected_count bigint; all_done boolean; current_phase text; receipt_step text;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.phase NOT IN ('primary_purged','external_purged') OR requested_store_code <> ALL(request_row.store_manifest)
       OR supplied_target_count < 0 OR supplied_affected_rows < 0 OR octet_length(supplied_postcondition_digest) <> 32
       OR supplied_result_code NOT IN ('ok','already_absent','not_configured','embedded_primary') THEN
        RAISE EXCEPTION 'erasure external close denied' USING ERRCODE = 'P0010';
    END IF;
    -- `supplied_target_count` is an API-shape compatibility value, never the
    -- authority for completion.  A worker can crash after marking some work;
    -- the durable work/checkpoint rows are the only count accepted here.
    SELECT count(*) INTO expected_count FROM public.erasure_external_work
     WHERE project_id = expected_project_id AND request_id = expected_request_id
       AND store_code = requested_store_code AND discovered_revision = request_row.closure_revision;
    IF EXISTS (
        SELECT 1 FROM public.erasure_external_work
         WHERE project_id = expected_project_id AND request_id = expected_request_id
           AND store_code = requested_store_code AND discovered_revision = request_row.closure_revision
           AND state <> 'verified'
    ) THEN RAISE EXCEPTION 'erasure external close denied' USING ERRCODE = 'P0014'; END IF;
    IF EXISTS (
        SELECT 1 FROM public.erasure_store_checkpoint
         WHERE project_id = expected_project_id AND request_id = expected_request_id
           AND store_code = requested_store_code
           AND prepared_revision = request_row.closure_revision
           AND verified_revision = request_row.closure_revision
    ) THEN
        -- A checkpoint is the durable aggregate proof.  A worker may die
        -- after its checkpoint/receipt transaction commits but before it can
        -- retain the in-memory aggregate it supplied here.  A successor must
        -- never manufacture a competing aggregate merely to replay this
        -- no-op close: exact current-revision verified state is sufficient.
        -- Work rows above are still required to be verified at this revision,
        -- so this branch cannot bless a stale or partial store pass.
        SELECT bool_and(checkpoint.verified_revision = request_row.closure_revision)
          INTO all_done
          FROM public.erasure_store_checkpoint AS checkpoint
         WHERE checkpoint.project_id = expected_project_id
           AND checkpoint.request_id = expected_request_id
           AND checkpoint.store_code = ANY(request_row.store_manifest);
        current_phase := request_row.phase;
        IF COALESCE(all_done, false) AND request_row.phase = 'primary_purged' THEN
            -- This is normally reached in the same close transaction as the
            -- final checkpoint.  Retaining it here makes the durable
            -- checkpoint a safe recovery seam if an older source had already
            -- committed all proofs but not the phase update.
            PERFORM public.tracebed_erasure_mint_capability(
                expected_project_id, expected_request_id, expected_generation,
                expected_lease_token, expected_owner, 'request_update'
            );
            UPDATE public.erasure_request
               SET phase = 'external_purged', last_code = 'in_progress',
                   updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
             WHERE project_id = expected_project_id AND request_id = expected_request_id;
            PERFORM public.tracebed_erasure_drop_capability(
                expected_project_id, expected_request_id, expected_generation,
                expected_lease_token, 'request_update'
            );
            current_phase := 'external_purged';
        END IF;
        RETURN QUERY SELECT current_phase, request_row.closure_revision;
        RETURN;
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'checkpoint'
    );
    UPDATE public.erasure_store_checkpoint
       SET verified_revision = request_row.closure_revision, postcondition_digest = supplied_postcondition_digest,
           result_code = supplied_result_code, verified_at = statement_timestamp()
     WHERE project_id = expected_project_id AND request_id = expected_request_id AND store_code = requested_store_code
       AND prepared_revision = request_row.closure_revision AND target_count = expected_count;
    IF NOT FOUND THEN RAISE EXCEPTION 'erasure external close denied' USING ERRCODE = 'P0014'; END IF;
    SELECT bool_and(checkpoint.verified_revision = request_row.closure_revision) INTO all_done
      FROM public.erasure_store_checkpoint AS checkpoint
     WHERE checkpoint.project_id = expected_project_id AND checkpoint.request_id = expected_request_id
       AND checkpoint.store_code = ANY(request_row.store_manifest);
    receipt_step := CASE requested_store_code
        WHEN 'trace_fs_v1' THEN 'trace_store'
        WHEN 'trace_s3_v1' THEN 'trace_store'
        WHEN 'valkey_v1' THEN 'valkey'
        WHEN 'vector_postgres' THEN 'vector'
        WHEN 'vector_qdrant' THEN 'vector'
        WHEN 'vector_none' THEN 'vector'
        WHEN 'graph_postgres' THEN 'graph'
        WHEN 'graph_age' THEN 'graph'
        WHEN 'graph_none' THEN 'graph'
        ELSE NULL
    END;
    IF receipt_step IS NULL THEN
        RAISE EXCEPTION 'erasure external close denied' USING ERRCODE = 'P0010';
    END IF;
    -- Appending a receipt advances the request-owned chain cursor.  Treat that
    -- as the same narrow request mutation capability as the phase transition;
    -- otherwise a valid store proof can be written but its chained receipt
    -- cannot atomically advance the request.
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'request_update'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'receipt_insert'
    );
    PERFORM public.tracebed_erasure_append_receipt(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        receipt_step, 'succeeded', supplied_result_code, supplied_affected_rows,
        request_row.closure_revision, supplied_postcondition_digest
    );
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert'
    );
    current_phase := request_row.phase;
    IF COALESCE(all_done,false) AND request_row.phase = 'primary_purged' THEN
        PERFORM public.tracebed_erasure_mint_capability(
            expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'request_update'
        );
        UPDATE public.erasure_request SET phase = 'external_purged', last_code = 'in_progress',
             updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
         WHERE project_id = expected_project_id AND request_id = expected_request_id;
        PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update');
        current_phase := 'external_purged';
    END IF;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'checkpoint');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update');
    RETURN QUERY SELECT current_phase, request_row.closure_revision;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_fail(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, requested_step text, requested_result text,
    requested_result_code text, supplied_affected_rows bigint, supplied_postcondition_digest bytea
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row record; delay_seconds integer;
BEGIN
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF requested_step NOT IN ('crypto','postgres','queue','valkey','trace_store','vector','graph','verify','complete')
       OR requested_result NOT IN ('retryable','blocked')
       OR requested_result_code NOT IN (
            'closure_changed','dependency_unavailable','dependency_timeout','verification_failed',
            'configuration_mismatch','store_refused','catalog_mismatch','unsafe_path','integrity_failed'
       ) OR supplied_affected_rows < 0 OR octet_length(supplied_postcondition_digest) <> 32 THEN
        RAISE EXCEPTION 'erasure failure denied' USING ERRCODE = 'P0010';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'request_update');
    PERFORM public.tracebed_erasure_mint_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'receipt_insert');
    PERFORM public.tracebed_erasure_append_receipt(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        requested_step, requested_result, requested_result_code, supplied_affected_rows,
        request_row.closure_revision, supplied_postcondition_digest
    );
    IF requested_result = 'retryable' THEN
        delay_seconds := LEAST(3600, 5 * (2 ^ LEAST(request_row.retry_count, 9))::integer);
        UPDATE public.erasure_request SET disposition = 'retry_wait', retry_count = request_row.retry_count + 1,
             retry_not_before = statement_timestamp() + make_interval(secs => delay_seconds),
             lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL, last_code = 'retry_scheduled',
             updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
         WHERE project_id = expected_project_id AND request_id = expected_request_id;
    ELSE
        UPDATE public.erasure_request SET disposition = 'operator_blocked', retry_not_before = NULL,
             lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL, last_code = 'operator_action_required',
             updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
         WHERE project_id = expected_project_id AND request_id = expected_request_id;
    END IF;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update');
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_resume_blocked(
    selected_request_id uuid, operator_code text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row record; cap_token uuid; resume_digest bytea;
BEGIN
    PERFORM public.tracebed_erasure_assert_caller();
    IF selected_request_id IS NULL OR operator_code IS DISTINCT FROM 'operator_resumed' THEN
        RAISE EXCEPTION 'erasure resume denied' USING ERRCODE = 'P0010';
    END IF;
    SELECT * INTO request_row FROM public.erasure_request WHERE request_id = selected_request_id FOR UPDATE;
    IF NOT FOUND OR request_row.disposition <> 'operator_blocked' OR request_row.phase = 'scope_complete'
       OR request_row.generation < 1 OR request_row.closure_revision < 1 THEN
        RAISE EXCEPTION 'erasure resume denied' USING ERRCODE = 'P0013';
    END IF;
    cap_token := gen_random_uuid();
    PERFORM public.tracebed_erasure_mint_request_capability(
        request_row.project_id, request_row.request_id, request_row.generation, cap_token
    );
    -- Resume has no live worker lease, but it is still an auditable state
    -- transition.  Mint transaction-local capabilities only for this fixed
    -- global operator action, append its chained receipt, and explicitly
    -- drop both before returning.
    INSERT INTO public.erasure_execution_capability (
        backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation
    ) VALUES (
        pg_backend_pid(), txid_current(), request_row.project_id, request_row.request_id,
        request_row.generation, cap_token, 'receipt_insert'
    ) ON CONFLICT DO NOTHING;
    UPDATE public.erasure_request SET disposition = 'active', retry_not_before = NULL,
         last_code = 'in_progress', updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = request_row.project_id AND request_id = request_row.request_id;
    resume_digest := sha256(convert_to('tracebed.erasure-resume/v1','UTF8')
        || uuid_send(request_row.project_id) || uuid_send(request_row.request_id)
        || int8send(request_row.closure_revision) || int4send(request_row.generation));
    -- ``queue`` is the closed administrative receipt step: it records a
    -- fixed-code operator resume without pretending that a crypto/store
    -- operation happened.  The append helper allocates its sequence, prior
    -- digest and per-step attempt under the already-held request row lock.
    PERFORM public.tracebed_erasure_append_receipt(
        request_row.project_id, request_row.request_id, request_row.generation, cap_token,
        'queue', 'succeeded', 'operator_resumed', 0, request_row.closure_revision, resume_digest
    );
    PERFORM public.tracebed_erasure_drop_capability(
        request_row.project_id, request_row.request_id, request_row.generation, cap_token, 'receipt_insert'
    );
    PERFORM public.tracebed_erasure_drop_capability(
        request_row.project_id, request_row.request_id, request_row.generation, cap_token, 'request_update'
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_verify_and_complete(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS TABLE (completed boolean, phase text, disposition text, closure_revision bigint, last_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row record; verify_digest bytea; complete_digest bytea;
BEGIN
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.phase = 'scope_complete' THEN
        RETURN QUERY SELECT true, request_row.phase, request_row.disposition, request_row.closure_revision, request_row.last_code;
        RETURN;
    END IF;
    IF request_row.phase <> 'external_purged'
       OR public.tracebed_erasure_primary_remaining(expected_project_id, expected_request_id) <> 0
       OR (SELECT count(*) FROM public.erasure_store_checkpoint
            WHERE project_id = expected_project_id AND request_id = expected_request_id
              AND store_code = ANY(request_row.store_manifest)
              AND verified_revision = request_row.closure_revision) <> 4 THEN
        RAISE EXCEPTION 'erasure verification denied' USING ERRCODE = 'P0014';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || expected_project_id::text, 0)
    );
    -- Re-read after the exclusive project lock, so an E2 late binder that won
    -- first cannot race finalization.  A later revision forces a new pass.
    SELECT * INTO request_row FROM public.erasure_request
     WHERE project_id = expected_project_id AND request_id = expected_request_id FOR UPDATE;
    IF request_row.closure_revision <> (SELECT closure_revision FROM public.erasure_request
                                         WHERE project_id = expected_project_id AND request_id = expected_request_id)
       OR request_row.phase <> 'external_purged' THEN
        RAISE EXCEPTION 'erasure closure changed' USING ERRCODE = 'P0014';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'fence_finalize');
    PERFORM public.tracebed_erasure_mint_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'request_update');
    PERFORM public.tracebed_erasure_mint_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'receipt_insert');
    UPDATE public.subject_fence SET state = 'erased', erased_at = statement_timestamp()
     WHERE project_id = expected_project_id AND request_id = expected_request_id AND state = 'fenced';
    UPDATE public.run_fence SET state = 'erased', erased_at = statement_timestamp()
     WHERE project_id = expected_project_id AND request_id = expected_request_id AND state = 'fenced';
    verify_digest := sha256(convert_to('tracebed.erasure-verify/v1','UTF8') || uuid_send(expected_project_id)
                     || uuid_send(expected_request_id) || int8send(request_row.closure_revision));
    UPDATE public.erasure_request SET phase = 'verified', verified_at = statement_timestamp(), last_code = 'in_progress',
         updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    PERFORM public.tracebed_erasure_append_receipt(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        'verify','succeeded','ok',0,request_row.closure_revision,verify_digest
    );
    complete_digest := public.tracebed_erasure_append_receipt(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        'complete','succeeded','ok',0,request_row.closure_revision,
        sha256(convert_to('tracebed.erasure-complete/v1','UTF8') || verify_digest)
    );
    UPDATE public.erasure_request SET phase = 'scope_complete', disposition = 'scope_complete',
         completed_at = statement_timestamp(), final_receipt_digest = complete_digest,
         lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL, retry_not_before = NULL,
         last_code = 'scope_complete', updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'fence_finalize');
    RETURN QUERY SELECT true, 'scope_complete'::text, 'scope_complete'::text, request_row.closure_revision, 'scope_complete'::text;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_inspect(selected_request_id uuid)
RETURNS TABLE (
    request_id uuid, scope text, phase text, disposition text, generation integer,
    retry_not_before timestamptz, last_code text, closure_revision bigint,
    pending_work bigint, verified_stores integer, total_stores integer
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.tracebed_erasure_assert_caller();
    IF selected_request_id IS NULL THEN RAISE EXCEPTION 'erasure inspect denied' USING ERRCODE = 'P0010'; END IF;
    RETURN QUERY
    SELECT request_row.request_id, request_row.scope, request_row.phase, request_row.disposition,
           request_row.generation, request_row.retry_not_before, request_row.last_code,
           request_row.closure_revision,
           (SELECT count(*) FROM public.erasure_external_work AS work
             WHERE work.project_id = request_row.project_id AND work.request_id = request_row.request_id
               AND work.discovered_revision = request_row.closure_revision AND work.state <> 'verified'),
           (SELECT count(*)::integer FROM public.erasure_store_checkpoint AS checkpoint
             WHERE checkpoint.project_id = request_row.project_id AND checkpoint.request_id = request_row.request_id
               AND checkpoint.verified_revision = request_row.closure_revision),
           cardinality(request_row.store_manifest)::integer
      FROM public.erasure_request AS request_row WHERE request_row.request_id = selected_request_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_request_status_by_actor(
    expected_principal_id uuid, expected_request_id uuid
) RETURNS TABLE (
    request_id uuid, scope text, phase text, disposition text, last_code text,
    limitation_codes text[], requested_at timestamptz, updated_at timestamptz, completed_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row record; project_state text;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user,'tracebed_api_group','member')
       OR expected_principal_id IS NULL OR expected_request_id IS NULL THEN
        RAISE EXCEPTION 'erasure status denied' USING ERRCODE = '42501';
    END IF;
    SELECT request.* INTO request_row
      FROM public.erasure_request AS request
     WHERE request.request_id = expected_request_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'erasure status absent' USING ERRCODE = 'P0002'; END IF;
    SELECT project.status INTO project_state
      FROM public.project AS project WHERE project.project_id = request_row.project_id;
    IF project_state = 'deleted' AND request_row.phase = 'scope_complete' THEN
        IF request_row.requested_principal_id IS DISTINCT FROM expected_principal_id
           OR NOT EXISTS (SELECT 1 FROM public.principal WHERE principal_id = expected_principal_id AND revoked_at IS NULL) THEN
            RAISE EXCEPTION 'erasure status absent' USING ERRCODE = 'P0002';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM public.agent_registration AS registration
         JOIN public.principal_grant AS grant_row ON grant_row.project_id = registration.project_id
           AND grant_row.principal_id = registration.principal_id
         JOIN public.principal AS principal ON principal.principal_id = registration.principal_id
         WHERE registration.principal_id = expected_principal_id AND registration.project_id = request_row.project_id
           AND registration.revoked_at IS NULL AND principal.revoked_at IS NULL
           AND grant_row.role = 'erasure_request' AND grant_row.revoked_at IS NULL
    ) THEN RAISE EXCEPTION 'erasure status absent' USING ERRCODE = 'P0002'; END IF;
    RETURN QUERY SELECT request_row.request_id, request_row.scope, request_row.phase, request_row.disposition,
       request_row.last_code, request_row.limitation_codes, request_row.requested_at,
       request_row.updated_at, request_row.completed_at;
END;
$$;

/* Deferred E3 ACLs: the artifact intentionally declares the externally
 * callable routines before the original c12 request tables.  The tables and
 * the remaining routines are installed later in this same atomic migration,
 * so apply the ACL surface only after all declarations exist.  No login or
 * membership is provisioned here.  The equivalent ACL block is appended at
 * the end of the migration. 
-- E3 is EXECUTE-only.  No erasure login/membership is provisioned by this
-- source artifact; deployment activation is a later, separately reviewed
-- login/HBA/Compose step.
REVOKE ALL ON public.erasure_external_work, public.erasure_store_checkpoint,
              public.erasure_execution_capability
    FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
         tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM tracebed_erasure_group;
REVOKE ALL ON FUNCTION public.tracebed_erasure_manifest_is_valid(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_frame(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_closure_digest(uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_manifest_digest(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_assert_caller() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_assert_lease(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_capable(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mint_capability(uuid,uuid,integer,uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_drop_capability(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_receipt_digest(uuid,uuid,bigint,integer,text,text,text,integer,bigint,bigint,bytea,bytea,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_append_receipt(uuid,uuid,integer,uuid,text,text,text,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_selected(uuid,text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mint_request_capability(uuid,uuid,integer,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_trace_manifest_digest_for_request(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_primary_remaining(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_next(text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_request(uuid,text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_renew(uuid,uuid,integer,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_crypto_step(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_trace_refs_batch(uuid,uuid,integer,uuid,text,bigint,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_seal_trace_manifest(uuid,uuid,integer,uuid,text,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_prepare_primary(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_external_work_batch(uuid,uuid,integer,uuid,text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mark_external_work(uuid,uuid,integer,uuid,text,uuid,bigint,bigint,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_close_external_step(uuid,uuid,integer,uuid,text,text,bigint,bigint,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_verify_and_complete(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_fail(uuid,uuid,integer,uuid,text,text,text,text,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_release(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_resume_blocked(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_inspect(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_request_status_by_actor(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_claim_next(text,integer,text[]),
    public.tracebed_erasure_claim_request(uuid,text,integer,text[]),
    public.tracebed_erasure_renew(uuid,uuid,integer,uuid,text,integer),
    public.tracebed_erasure_crypto_step(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_trace_refs_batch(uuid,uuid,integer,uuid,text,bigint,uuid,text,integer),
    public.tracebed_erasure_seal_trace_manifest(uuid,uuid,integer,uuid,text,bigint,bigint,bytea),
    public.tracebed_erasure_prepare_primary(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer),
    public.tracebed_erasure_external_work_batch(uuid,uuid,integer,uuid,text,text,integer),
    public.tracebed_erasure_mark_external_work(uuid,uuid,integer,uuid,text,uuid,bigint,bigint,bytea,text),
    public.tracebed_erasure_close_external_step(uuid,uuid,integer,uuid,text,text,bigint,bigint,bytea,text),
    public.tracebed_erasure_verify_and_complete(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_fail(uuid,uuid,integer,uuid,text,text,text,text,bigint,bytea),
    public.tracebed_erasure_release(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_resume_blocked(uuid,text), public.tracebed_erasure_inspect(uuid)
TO tracebed_erasure_group;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_request_status_by_actor(uuid,uuid)
TO tracebed_api_group;
*/

-- Trigger-only attribution guards.  They are SECURITY DEFINER so a runtime
-- role cannot turn a lack of direct SELECT on a protected binding table into
-- a caller-controlled digest array.  Every function fixes search_path and
-- derives its own digest set; no input array is trusted.
CREATE FUNCTION public.tracebed_run_subject_attribution_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    SELECT COALESCE(array_agg(binding.subject_digest ORDER BY binding.subject_digest),
                    ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')])
      INTO NEW.subject_digests
      FROM public.trace_subject AS binding
     WHERE binding.project_id = NEW.project_id AND binding.run_id = NEW.run_id;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.tracebed_memory_subject_attribution_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    SELECT COALESCE(memory_row.subject_digests,
                    ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')])
      INTO NEW.subject_digests
      FROM public.memory_item AS memory_row
     WHERE memory_row.project_id = NEW.project_id AND memory_row.id = NEW.memory_id;
    IF NOT FOUND THEN
        NEW.subject_digests := ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')];
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.tracebed_memory_link_subject_attribution_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.memory_item AS memory_row
         WHERE memory_row.project_id = NEW.project_id AND memory_row.id IN (NEW.src_id, NEW.dst_id)
    ) THEN
        SELECT COALESCE(array_agg(DISTINCT digest ORDER BY digest), '{}'::bytea[])
          INTO NEW.subject_digests
          FROM public.memory_item AS memory_row
          CROSS JOIN LATERAL unnest(memory_row.subject_digests) AS item(digest)
         WHERE memory_row.project_id = NEW.project_id AND memory_row.id IN (NEW.src_id, NEW.dst_id);
    ELSE
        NEW.subject_digests := ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')];
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.tracebed_memory_item_subject_attribution_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.subject_tag IS NOT NULL THEN
        -- A legacy/direct memory tag is one authoritative contributor, not a
        -- reason to discard normalized run provenance.  Refine the project
        -- sentinel away once either source supplies a concrete digest.
        WITH concrete AS (
            SELECT public.tracebed_subject_digest(NEW.project_id, NEW.subject_tag) AS digest
            UNION
            SELECT digest
              FROM unnest(COALESCE(NEW.subject_digests, '{}'::bytea[])) AS item(digest)
             WHERE digest <> public.tracebed_subject_digest(NEW.project_id, '__project__')
        )
        SELECT array_agg(digest ORDER BY digest) INTO NEW.subject_digests FROM concrete;
    ELSIF NEW.subject_digests IS NULL THEN
        NEW.subject_digests := ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')];
    ELSIF EXISTS (
        SELECT 1
          FROM unnest(NEW.subject_digests) AS item(digest)
         WHERE digest <> public.tracebed_subject_digest(NEW.project_id, '__project__')
    ) THEN
        SELECT array_agg(digest ORDER BY digest) INTO NEW.subject_digests
          FROM (
              SELECT DISTINCT digest
                FROM unnest(NEW.subject_digests) AS item(digest)
               WHERE digest <> public.tracebed_subject_digest(NEW.project_id, '__project__')
          ) AS concrete;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.tracebed_project_subject_attribution_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    NEW.subject_digests := ARRAY[public.tracebed_subject_digest(NEW.project_id, '__project__')];
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS aa_run_owner_subject_attribution_guard ON run_owner;
CREATE TRIGGER aa_run_owner_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON run_owner
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_trace_index_subject_attribution_guard ON trace_index;
CREATE TRIGGER aa_trace_index_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON trace_index
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_work_queue_subject_attribution_guard ON work_queue;
CREATE TRIGGER aa_work_queue_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON work_queue
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_dead_letter_subject_attribution_guard ON dead_letter;
CREATE TRIGGER aa_dead_letter_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON dead_letter
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_outcome_event_subject_attribution_guard ON outcome_event;
CREATE TRIGGER aa_outcome_event_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON outcome_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_trace_learning_job_subject_attribution_guard ON trace_learning_job;
CREATE TRIGGER aa_trace_learning_job_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON trace_learning_job
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_injection_log_subject_attribution_guard ON injection_log;
CREATE TRIGGER aa_injection_log_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON injection_log
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_retrieval_event_subject_attribution_guard ON retrieval_event;
CREATE TRIGGER aa_retrieval_event_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON retrieval_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_blackboard_entry_subject_attribution_guard ON blackboard_entry;
CREATE TRIGGER aa_blackboard_entry_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON blackboard_entry
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_subject_attribution_guard();

DROP TRIGGER IF EXISTS aa_review_queue_subject_attribution_guard ON review_queue;
CREATE TRIGGER aa_review_queue_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON review_queue
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_memory_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_memory_status_log_subject_attribution_guard ON memory_status_log;
CREATE TRIGGER aa_memory_status_log_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON memory_status_log
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_memory_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_memory_q_update_subject_attribution_guard ON memory_q_update;
CREATE TRIGGER aa_memory_q_update_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON memory_q_update
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_memory_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_memory_link_subject_attribution_guard ON memory_link;
CREATE TRIGGER aa_memory_link_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON memory_link
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_memory_link_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_memory_item_subject_attribution_guard ON memory_item;
CREATE TRIGGER aa_memory_item_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON memory_item
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_memory_item_subject_attribution_guard();

DROP TRIGGER IF EXISTS aa_derived_state_subject_attribution_guard ON derived_state;
CREATE TRIGGER aa_derived_state_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON derived_state
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_project_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_invalidation_event_subject_attribution_guard ON invalidation_event;
CREATE TRIGGER aa_invalidation_event_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON invalidation_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_project_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_spend_ledger_subject_attribution_guard ON spend_ledger;
CREATE TRIGGER aa_spend_ledger_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON spend_ledger
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_project_subject_attribution_guard();
DROP TRIGGER IF EXISTS aa_killswitch_state_subject_attribution_guard ON killswitch_state;
CREATE TRIGGER aa_killswitch_state_subject_attribution_guard
    BEFORE INSERT OR UPDATE ON killswitch_state
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_project_subject_attribution_guard();

CREATE TABLE subject_fence (
    project_id uuid NOT NULL,
    subject_digest bytea NOT NULL,
    state text NOT NULL DEFAULT 'live',
    request_id uuid,
    first_seen_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    fenced_at timestamptz,
    erased_at timestamptz,
    PRIMARY KEY (project_id, subject_digest),
    CONSTRAINT subject_fence_digest_ck CHECK (octet_length(subject_digest) = 32),
    CONSTRAINT subject_fence_state_ck CHECK (state IN ('live', 'fenced', 'erased')),
    CONSTRAINT subject_fence_time_ck CHECK (isfinite(first_seen_at)
        AND (fenced_at IS NULL OR (isfinite(fenced_at) AND fenced_at >= first_seen_at))
        AND (erased_at IS NULL OR (isfinite(erased_at) AND fenced_at IS NOT NULL AND erased_at >= fenced_at))),
    CONSTRAINT subject_fence_shape_ck CHECK (
        (state = 'live' AND request_id IS NULL AND fenced_at IS NULL AND erased_at IS NULL)
        OR (state = 'fenced' AND request_id IS NOT NULL AND fenced_at IS NOT NULL AND erased_at IS NULL)
        OR (state = 'erased' AND request_id IS NOT NULL AND fenced_at IS NOT NULL AND erased_at IS NOT NULL)
    )
) PARTITION BY LIST (project_id);

CREATE TABLE run_fence (
    project_id uuid NOT NULL,
    run_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'live',
    request_id uuid,
    first_seen_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    fenced_at timestamptz,
    erased_at timestamptz,
    PRIMARY KEY (project_id, run_id),
    CONSTRAINT run_fence_state_ck CHECK (state IN ('live', 'fenced', 'erased')),
    CONSTRAINT run_fence_time_ck CHECK (isfinite(first_seen_at)
        AND (fenced_at IS NULL OR (isfinite(fenced_at) AND fenced_at >= first_seen_at))
        AND (erased_at IS NULL OR (isfinite(erased_at) AND fenced_at IS NOT NULL AND erased_at >= fenced_at))),
    CONSTRAINT run_fence_shape_ck CHECK (
        (state = 'live' AND request_id IS NULL AND fenced_at IS NULL AND erased_at IS NULL)
        OR (state = 'fenced' AND request_id IS NOT NULL AND fenced_at IS NOT NULL AND erased_at IS NULL)
        OR (state = 'erased' AND request_id IS NOT NULL AND fenced_at IS NOT NULL AND erased_at IS NOT NULL)
    )
) PARTITION BY LIST (project_id);

CREATE TABLE erase_run_set (
    project_id uuid NOT NULL,
    request_id uuid NOT NULL,
    run_id uuid NOT NULL,
    discovered_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (project_id, request_id, run_id),
    CONSTRAINT erase_run_set_discovered_at_ck CHECK (isfinite(discovered_at))
) PARTITION BY LIST (project_id);

CREATE TABLE erase_mem_set (
    project_id uuid NOT NULL,
    request_id uuid NOT NULL,
    memory_id uuid NOT NULL,
    closure_depth integer NOT NULL,
    discovered_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (project_id, request_id, memory_id),
    CONSTRAINT erase_mem_set_closure_depth_ck CHECK (closure_depth BETWEEN 0 AND 1024),
    CONSTRAINT erase_mem_set_discovered_at_ck CHECK (isfinite(discovered_at))
) PARTITION BY LIST (project_id);

-- Normalized provenance from a run to each persisted memory it can create or
-- influence.  It is monotone and lets binding/erasure propagate attribution
-- without a hidden O(all-project-memories) JSON scan.
CREATE TABLE run_memory_binding (
    project_id uuid NOT NULL,
    run_id uuid NOT NULL,
    memory_id uuid NOT NULL,
    bound_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (project_id, run_id, memory_id),
    CONSTRAINT run_memory_binding_bound_at_ck CHECK (isfinite(bound_at))
) PARTITION BY LIST (project_id);

-- A one-transaction capability used only by the profiled late binder.  It is
-- deliberately not a request ledger or an application-visible queue: its
-- `(backend_pid, txid)` pair prevents a runtime principal from carrying the
-- exception into another transaction, and all runtime roles are revoked from
-- the relation below.  The generic write guard consults it only for the one
-- digest-only `trace_subject` insert needed to record a late fenced target.
CREATE TABLE erasure_late_bind_capability (
    backend_pid integer NOT NULL,
    transaction_id bigint NOT NULL,
    project_id uuid NOT NULL,
    run_id uuid NOT NULL,
    request_id uuid NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (backend_pid, transaction_id),
    CONSTRAINT erasure_late_bind_capability_time_ck CHECK (isfinite(issued_at))
);

-- A worker snapshot is a transaction-scoped proof, not a caller supplied
-- digest assertion.  The only dependent v2 key write is allowed to consume
-- this opaque owner-written capability on the same backend/xid.  A later
-- transaction cannot replay it, and runtime roles have no table privilege.
-- Old rows are pruned when that backend takes its next snapshot; their xid
-- can never satisfy the exact-current-xid predicate below.
CREATE TABLE erasure_snapshot_capability (
    backend_pid integer NOT NULL,
    transaction_id bigint NOT NULL,
    project_id uuid NOT NULL,
    run_id uuid NOT NULL,
    subject_digests bytea[] NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (backend_pid, transaction_id),
    CONSTRAINT erasure_snapshot_capability_digests_ck
        CHECK (public.subject_digests_are_valid(subject_digests)),
    CONSTRAINT erasure_snapshot_capability_time_ck CHECK (isfinite(issued_at))
);

CREATE TABLE erasure_request (
    request_id uuid NOT NULL DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL,
    scope text NOT NULL,
    subject_digest bytea,
    requested_principal_id uuid NOT NULL,
    requested_agent_type_id uuid NOT NULL,
    requested_grant_id uuid NOT NULL,
    requested_by_session name NOT NULL DEFAULT session_user,
    phase text NOT NULL DEFAULT 'requested',
    disposition text NOT NULL DEFAULT 'active',
    generation integer NOT NULL DEFAULT 0,
    lease_token uuid,
    lease_owner text,
    lease_expires_at timestamptz,
    retry_not_before timestamptz,
    last_code text,
    limitation_codes text[] NOT NULL DEFAULT '{}'::text[],
    requested_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    final_receipt_digest bytea,
    PRIMARY KEY (project_id, request_id),
    CONSTRAINT erasure_request_scope_ck CHECK (scope IN ('subject', 'project')),
    CONSTRAINT erasure_request_scope_shape_ck CHECK (
        (scope = 'subject' AND subject_digest IS NOT NULL AND octet_length(subject_digest) = 32)
        OR (scope = 'project' AND subject_digest IS NULL)
    ),
    -- These FKs are intentionally limited to the unpartitioned authority
    -- registry.  Target/run/memory rows remain partition-lifecycle managed,
    -- so their relationship is represented by immutable closure receipts
    -- rather than a cross-partition FK that would block project teardown.
    CONSTRAINT erasure_request_project_fk FOREIGN KEY (project_id)
        REFERENCES project(project_id),
    CONSTRAINT erasure_request_actor_registration_fk
        FOREIGN KEY (requested_principal_id, project_id)
        REFERENCES agent_registration(principal_id, project_id),
    CONSTRAINT erasure_request_actor_agent_type_fk
        FOREIGN KEY (project_id, requested_agent_type_id)
        REFERENCES agent_type(project_id, agent_type_id),
    CONSTRAINT erasure_request_actor_grant_fk FOREIGN KEY (requested_grant_id)
        REFERENCES principal_grant(grant_id),
    CONSTRAINT erasure_request_phase_ck CHECK (phase IN ('requested','fenced','crypto_erased','primary_purged','external_purged','verified','scope_complete')),
    CONSTRAINT erasure_request_disposition_ck CHECK (disposition IN ('active','retry_wait','operator_blocked','scope_complete')),
    CONSTRAINT erasure_request_generation_ck CHECK (generation >= 0),
    CONSTRAINT erasure_request_lease_ck CHECK (
        (lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL)
        OR (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL
            AND lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$'
            AND isfinite(lease_expires_at) AND lease_expires_at >= updated_at)
    ),
    CONSTRAINT erasure_request_code_ck CHECK (last_code IS NULL OR last_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT erasure_request_limits_ck CHECK (public.tracebed_erasure_codes_are_valid(limitation_codes)),
    CONSTRAINT erasure_request_time_ck CHECK (isfinite(requested_at) AND isfinite(updated_at)
        AND updated_at >= requested_at AND (completed_at IS NULL OR (isfinite(completed_at) AND completed_at >= requested_at))),
    CONSTRAINT erasure_request_retry_ck CHECK (
        (disposition = 'retry_wait') = (retry_not_before IS NOT NULL)
        AND (retry_not_before IS NULL OR (isfinite(retry_not_before) AND retry_not_before >= updated_at))
    ),
    CONSTRAINT erasure_request_terminal_pair_ck CHECK (
        (phase = 'scope_complete') = (disposition = 'scope_complete')
    ),
    CONSTRAINT erasure_request_complete_ck CHECK (
        (phase = 'scope_complete' AND disposition = 'scope_complete'
         AND completed_at IS NOT NULL AND final_receipt_digest IS NOT NULL
         AND octet_length(final_receipt_digest) = 32
         AND last_code IS NOT DISTINCT FROM 'scope_complete'
         AND lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL
         AND retry_not_before IS NULL)
        OR
        (NOT (phase = 'scope_complete' AND disposition = 'scope_complete')
         AND completed_at IS NULL AND final_receipt_digest IS NULL)
    )
);
CREATE UNIQUE INDEX erasure_request_target_uq ON erasure_request (project_id, scope, subject_digest) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX erasure_request_one_active_project_uq ON erasure_request (project_id)
    WHERE disposition <> 'scope_complete';
CREATE INDEX erasure_request_claim_idx ON erasure_request (disposition, retry_not_before, requested_at, request_id)
    WHERE disposition IN ('active', 'retry_wait');

CREATE TABLE erasure_step_receipt (
    project_id uuid NOT NULL,
    request_id uuid NOT NULL,
    step_seq bigint NOT NULL,
    step_code text NOT NULL,
    attempt integer NOT NULL,
    generation integer NOT NULL,
    result text NOT NULL,
    affected_rows bigint NOT NULL DEFAULT 0,
    postcondition_digest bytea NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    receipt_digest bytea NOT NULL,
    PRIMARY KEY (project_id, request_id, step_seq),
    CONSTRAINT erasure_step_receipt_request_fk FOREIGN KEY (project_id, request_id)
        REFERENCES erasure_request(project_id, request_id),
    CONSTRAINT erasure_step_receipt_seq_ck CHECK (step_seq >= 1),
    CONSTRAINT erasure_step_receipt_step_ck CHECK (step_code IN ('fence','crypto','postgres','queue','valkey','trace_store','vector','graph','verify','complete')),
    CONSTRAINT erasure_step_receipt_attempt_ck CHECK (attempt >= 1),
    CONSTRAINT erasure_step_receipt_generation_ck CHECK (generation >= 1),
    CONSTRAINT erasure_step_receipt_result_ck CHECK (result IN ('succeeded','retryable','blocked')),
    CONSTRAINT erasure_step_receipt_rows_ck CHECK (affected_rows >= 0),
    CONSTRAINT erasure_step_receipt_digest_ck CHECK (octet_length(postcondition_digest) = 32 AND octet_length(receipt_digest) = 32),
    CONSTRAINT erasure_step_receipt_time_ck CHECK (isfinite(started_at) AND isfinite(finished_at) AND finished_at >= started_at),
    UNIQUE (project_id, request_id, step_code, attempt),
    UNIQUE (receipt_digest)
);

CREATE FUNCTION public.erasure_request_enforce_transition() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'erasure requests cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.phase <> 'requested' OR NEW.disposition <> 'active' OR NEW.generation <> 0
           OR NEW.lease_token IS NOT NULL OR NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at IS NOT NULL
           OR NEW.retry_not_before IS NOT NULL OR NEW.last_code IS NOT NULL
           OR cardinality(NEW.limitation_codes) <> 0 OR NEW.completed_at IS NOT NULL
           OR NEW.final_receipt_digest IS NOT NULL THEN
            RAISE EXCEPTION 'erasure request insert is not pristine' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.project_id IS DISTINCT FROM OLD.project_id OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.scope IS DISTINCT FROM OLD.scope OR NEW.subject_digest IS DISTINCT FROM OLD.subject_digest
       OR NEW.requested_principal_id IS DISTINCT FROM OLD.requested_principal_id
       OR NEW.requested_agent_type_id IS DISTINCT FROM OLD.requested_agent_type_id
       OR NEW.requested_grant_id IS DISTINCT FROM OLD.requested_grant_id
       OR NEW.requested_by_session IS DISTINCT FROM OLD.requested_by_session
       OR NEW.requested_at IS DISTINCT FROM OLD.requested_at THEN
        RAISE EXCEPTION 'erasure request identity is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF NOT isfinite(NEW.updated_at) OR NEW.updated_at <= OLD.updated_at
       OR NOT (OLD.limitation_codes <@ NEW.limitation_codes) THEN
        RAISE EXCEPTION 'erasure request update is invalid' USING ERRCODE = '23514';
    END IF;
    IF NOT (
        NEW.phase = OLD.phase
        OR (OLD.phase = 'requested' AND NEW.phase = 'fenced')
        OR (OLD.phase = 'fenced' AND NEW.phase = 'crypto_erased')
        OR (OLD.phase = 'crypto_erased' AND NEW.phase = 'primary_purged')
        OR (OLD.phase = 'primary_purged' AND NEW.phase = 'external_purged')
        OR (OLD.phase = 'external_purged' AND NEW.phase = 'verified')
        OR (OLD.phase = 'verified' AND NEW.phase = 'scope_complete')
    ) OR OLD.phase = 'scope_complete' THEN
        RAISE EXCEPTION 'erasure request phase transition is invalid' USING ERRCODE = '23514';
    END IF;
    IF NOT (
        NEW.disposition = OLD.disposition
        OR (OLD.disposition = 'active' AND NEW.disposition IN ('retry_wait','operator_blocked','scope_complete'))
        OR (OLD.disposition = 'retry_wait' AND NEW.disposition IN ('active','operator_blocked'))
        OR (OLD.disposition = 'operator_blocked' AND NEW.disposition = 'active')
    ) OR OLD.disposition = 'scope_complete' THEN
        RAISE EXCEPTION 'erasure request disposition transition is invalid' USING ERRCODE = '23514';
    END IF;
    -- Completion is one terminal transition, not two independently valid
    -- state changes. It may happen only from a fully verified active request,
    -- carries the final receipt in that same write, and releases any lease
    -- atomically. The table constraint above remains a direct-write fence.
    IF NEW.phase = 'scope_complete' OR NEW.disposition = 'scope_complete' THEN
        IF OLD.phase IS DISTINCT FROM 'verified' OR OLD.disposition IS DISTINCT FROM 'active'
           OR NEW.phase IS DISTINCT FROM 'scope_complete' OR NEW.disposition IS DISTINCT FROM 'scope_complete'
           OR NEW.completed_at IS NULL OR NEW.final_receipt_digest IS NULL
           OR octet_length(NEW.final_receipt_digest) IS DISTINCT FROM 32
           OR NEW.last_code IS DISTINCT FROM 'scope_complete'
           OR NEW.lease_token IS NOT NULL OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_expires_at IS NOT NULL OR NEW.retry_not_before IS NOT NULL THEN
            RAISE EXCEPTION 'erasure request completion is not atomic' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.completed_at IS NOT NULL OR NEW.final_receipt_digest IS NOT NULL THEN
        RAISE EXCEPTION 'erasure request completion is not terminal' USING ERRCODE = '23514';
    END IF;
    IF NEW.generation = OLD.generation THEN
        IF OLD.lease_token IS NULL AND NEW.lease_token IS NOT NULL THEN
            RAISE EXCEPTION 'erasure request lease acquisition requires a generation' USING ERRCODE = '23514';
        END IF;
        IF OLD.lease_token IS NOT NULL AND NEW.lease_token IS NOT NULL AND (
            NEW.lease_token IS DISTINCT FROM OLD.lease_token OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
        ) THEN
            RAISE EXCEPTION 'erasure request lease identity is immutable' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.generation = OLD.generation + 1
          AND OLD.lease_token IS NULL AND NEW.lease_token IS NOT NULL
          AND NEW.lease_owner IS NOT NULL AND NEW.lease_expires_at IS NOT NULL THEN
        NULL;
    ELSE
        RAISE EXCEPTION 'erasure request generation is invalid' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER erasure_request_transition_guard
    BEFORE INSERT OR UPDATE OR DELETE ON erasure_request
    FOR EACH ROW EXECUTE FUNCTION public.erasure_request_enforce_transition();

CREATE FUNCTION public.erasure_step_receipt_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'erasure step receipts are append-only' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER erasure_step_receipt_append_only_guard
    BEFORE UPDATE OR DELETE ON erasure_step_receipt
    FOR EACH ROW EXECUTE FUNCTION public.erasure_step_receipt_append_only();

-- A fence is durable authority, not an advisory cache.  Its target and first
-- observation are immutable, assignment happens once, and state may only
-- progress forward.  Runtime identities have no direct DML ACL on these
-- relations; this trigger also keeps a privileged accidental UPDATE from
-- reviving a fenced lineage.
CREATE FUNCTION public.tracebed_fence_enforce_transition() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'erasure fences cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'live' OR NEW.request_id IS NOT NULL
           OR NEW.fenced_at IS NOT NULL OR NEW.erased_at IS NOT NULL THEN
            RAISE EXCEPTION 'new erasure fences must be live' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR (to_jsonb(NEW) ->> CASE WHEN TG_TABLE_NAME = 'subject_fence'
                                   THEN 'subject_digest' ELSE 'run_id' END)
          IS DISTINCT FROM
          (to_jsonb(OLD) ->> CASE WHEN TG_TABLE_NAME = 'subject_fence'
                                   THEN 'subject_digest' ELSE 'run_id' END)
       OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at THEN
        RAISE EXCEPTION 'erasure fence identity is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'live' THEN
        IF NEW.state <> 'fenced' OR NEW.request_id IS NULL
           OR NEW.fenced_at IS NULL OR NEW.erased_at IS NOT NULL THEN
            RAISE EXCEPTION 'live erasure fence must advance to fenced' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'fenced' THEN
        IF NEW.request_id IS DISTINCT FROM OLD.request_id
           OR NEW.fenced_at IS DISTINCT FROM OLD.fenced_at
           OR NEW.state <> 'erased' OR NEW.erased_at IS NULL THEN
            RAISE EXCEPTION 'fenced erasure fence must advance to erased' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'erased erasure fence is immutable' USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER subject_fence_transition_guard
    BEFORE INSERT OR UPDATE OR DELETE ON subject_fence
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_fence_enforce_transition();
CREATE TRIGGER run_fence_transition_guard
    BEFORE INSERT OR UPDATE OR DELETE ON run_fence
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_fence_enforce_transition();

CREATE FUNCTION public.tracebed_erasure_set_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'erasure closure sets are append-only' USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER erase_run_set_append_only_guard
    BEFORE UPDATE OR DELETE ON erase_run_set
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_erasure_set_append_only();
CREATE TRIGGER erase_mem_set_append_only_guard
    BEFORE UPDATE OR DELETE ON erase_mem_set
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_erasure_set_append_only();

CREATE FUNCTION public.tracebed_run_memory_binding_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' AND EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid()
           AND capability.transaction_id = txid_current()
           AND capability.project_id = OLD.project_id
           AND capability.operation = 'primary_purge'
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'run memory bindings are append-only' USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER run_memory_binding_append_only_guard
    BEFORE UPDATE OR DELETE ON run_memory_binding
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_run_memory_binding_append_only();

CREATE TABLE erasure_cutover_state (
    singleton boolean PRIMARY KEY CHECK (singleton),
    cutover_at timestamptz NOT NULL,
    ingress_attested_at timestamptz NOT NULL,
    activated_at timestamptz,
    first_activity_at timestamptz,
    rollback_quarantined_at timestamptz,
    legacy_subject_key_rows bigint NOT NULL CHECK (legacy_subject_key_rows >= 0),
    legacy_trace_subject_rows bigint NOT NULL CHECK (legacy_trace_subject_rows >= 0),
    legacy_memory_item_rows bigint NOT NULL CHECK (legacy_memory_item_rows >= 0),
    -- Exact migration-created run→memory baseline.  A preactivity rollback
    -- may retain this deterministic backfill, but any runtime append changes
    -- the count/digest receipt and is irreversible.
    legacy_run_memory_binding_rows bigint NOT NULL CHECK (legacy_run_memory_binding_rows >= 0),
    binding_backfill_digest bytea NOT NULL CHECK (octet_length(binding_backfill_digest) = 32),
    CONSTRAINT erasure_cutover_state_shape_ck CHECK (
        isfinite(cutover_at) AND isfinite(ingress_attested_at) AND cutover_at = ingress_attested_at
        AND (activated_at IS NULL OR (isfinite(activated_at) AND activated_at >= cutover_at))
        AND (first_activity_at IS NULL OR (activated_at IS NOT NULL AND isfinite(first_activity_at) AND first_activity_at >= activated_at))
        AND (rollback_quarantined_at IS NULL OR (activated_at IS NOT NULL AND isfinite(rollback_quarantined_at) AND rollback_quarantined_at >= activated_at))
        AND NOT (first_activity_at IS NOT NULL AND rollback_quarantined_at IS NOT NULL)
    )
);

ALTER TABLE subject_fence ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject_fence FORCE ROW LEVEL SECURITY;
ALTER TABLE run_fence ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_fence FORCE ROW LEVEL SECURITY;
ALTER TABLE erase_run_set ENABLE ROW LEVEL SECURITY;
ALTER TABLE erase_run_set FORCE ROW LEVEL SECURITY;
ALTER TABLE erase_mem_set ENABLE ROW LEVEL SECURITY;
ALTER TABLE erase_mem_set FORCE ROW LEVEL SECURITY;
ALTER TABLE run_memory_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_memory_binding FORCE ROW LEVEL SECURITY;
ALTER TABLE erasure_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE erasure_request FORCE ROW LEVEL SECURITY;
ALTER TABLE erasure_step_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE erasure_step_receipt FORCE ROW LEVEL SECURITY;
ALTER TABLE erasure_cutover_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE erasure_cutover_state FORCE ROW LEVEL SECURITY;
CREATE POLICY subject_fence_isolation ON subject_fence
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid)
    WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY run_fence_isolation ON run_fence
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid)
    WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY erase_run_set_isolation ON erase_run_set
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid)
    WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY erase_mem_set_isolation ON erase_mem_set
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid)
    WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY run_memory_binding_isolation ON run_memory_binding
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid)
    WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY erasure_request_isolation ON erasure_request
    -- The owner-only branch is for profiled SECURITY DEFINER routines such
    -- as the global worker scheduler.  Runtime API/worker sessions keep the
    -- project-GUC branch and still have no direct table ACL, so this cannot
    -- become a cross-project request-state oracle.
    USING (
        current_user = 'tracebed_owner'
        OR project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid
    )
    WITH CHECK (
        current_user = 'tracebed_owner'
        OR project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid
    );
CREATE POLICY erasure_step_receipt_isolation ON erasure_step_receipt
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid)
    WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY erasure_cutover_state_owner_only ON erasure_cutover_state
    USING (session_user = 'tracebed_owner' AND current_user = 'tracebed_owner')
    WITH CHECK (session_user = 'tracebed_owner' AND current_user = 'tracebed_owner');

-- Create every E1 child before any activity marker exists.  The exact name,
-- RLS predicate, and indexes match ddl.py's closed partition vocabulary.
DO $$
DECLARE
    project_value uuid;
    parent_name text;
    leaf_name text;
    policy_name text;
BEGIN
    FOR project_value IN
        SELECT project_id FROM project
         WHERE status IN ('active', 'suspended') AND deleted_at IS NULL
    LOOP
        FOREACH parent_name IN ARRAY ARRAY[
            'subject_fence','run_fence','erase_run_set','erase_mem_set','run_memory_binding'
        ] LOOP
            leaf_name := parent_name || '_p_' || replace(project_value::text, '-', '');
            policy_name := leaf_name || '_isolation';
            EXECUTE format('CREATE TABLE public.%I PARTITION OF public.%I FOR VALUES IN (%L)', leaf_name, parent_name, project_value);
            EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', leaf_name);
            EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', leaf_name);
            EXECUTE format(
                'CREATE POLICY %I ON public.%I USING (project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid) '
                || 'WITH CHECK (project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid)',
                policy_name, leaf_name
            );
            IF parent_name = 'subject_fence' THEN
                EXECUTE format('CREATE INDEX %I ON public.%I (state, subject_digest)', leaf_name || '_state', leaf_name);
            ELSIF parent_name = 'run_fence' THEN
                EXECUTE format('CREATE INDEX %I ON public.%I (state, run_id)', leaf_name || '_state', leaf_name);
            ELSIF parent_name = 'run_memory_binding' THEN
                EXECUTE format('CREATE INDEX %I ON public.%I (run_id, memory_id)', leaf_name || '_run', leaf_name);
            END IF;
        END LOOP;
    END LOOP;
END;
$$;

-- The indexes were created before their populated leaves were updated above.
-- Assert their exact names here rather than rebuilding them after the
-- backfill (which would set ``indcheckxmin`` on a real c11 upgrade).
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
        IF pg_catalog.to_regclass('public.' || leaf_name || '_subject') IS NULL THEN
            RAISE EXCEPTION 'missing c12 trace subject index' USING ERRCODE = '55000';
        END IF;

        FOREACH leaf_name IN ARRAY ARRAY[
            'memory_item_p_' || replace(project_value::text, '-', ''),
            'outcome_event_p_' || replace(project_value::text, '-', ''),
            'invalidation_event_p_' || replace(project_value::text, '-', ''),
            'trace_learning_job_p_' || replace(project_value::text, '-', ''),
            'run_owner_p_' || replace(project_value::text, '-', ''),
            'trace_index_p_' || replace(project_value::text, '-', ''),
            'injection_log_p_' || replace(project_value::text, '-', ''),
            'retrieval_event_p_' || replace(project_value::text, '-', ''),
            'blackboard_entry_p_' || replace(project_value::text, '-', ''),
            'memory_link_p_' || replace(project_value::text, '-', ''),
            'derived_state_p_' || replace(project_value::text, '-', ''),
            'spend_ledger_p_' || replace(project_value::text, '-', ''),
            'review_queue_p_' || replace(project_value::text, '-', ''),
            'memory_status_log_p_' || replace(project_value::text, '-', ''),
            'memory_q_update_p_' || replace(project_value::text, '-', '')
        ] LOOP
            IF pg_catalog.to_regclass('public.' || leaf_name || '_subjects') IS NULL THEN
                RAISE EXCEPTION 'missing c12 subject attribution index' USING ERRCODE = '55000';
            END IF;
        END LOOP;
    END LOOP;
END;
$$;

CREATE FUNCTION public.tracebed_mark_erasure_activity() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- The marker is a one-way cutover receipt.  Once present, ordinary
    -- protected writes must only read it; an unconditional singleton lock
    -- here would serialize unrelated projects forever after first activity.
    PERFORM 1
      FROM public.erasure_cutover_state
     WHERE singleton
       AND activated_at IS NOT NULL
       AND rollback_quarantined_at IS NULL
       AND first_activity_at IS NOT NULL;
    IF FOUND THEN
        RETURN;
    END IF;

    UPDATE public.erasure_cutover_state
       SET first_activity_at = statement_timestamp()
     WHERE singleton
       AND activated_at IS NOT NULL
       AND rollback_quarantined_at IS NULL
       AND first_activity_at IS NULL;
    IF NOT FOUND THEN
        -- Two unrelated protected writes can race on the one-time receipt.
        -- The losing conditional UPDATE is valid if the winner has already
        -- installed the same activated, non-quarantined marker.  Re-read
        -- rather than turning that legitimate first-write race into a 42501.
        PERFORM 1
          FROM public.erasure_cutover_state
         WHERE singleton
           AND activated_at IS NOT NULL
           AND rollback_quarantined_at IS NULL
           AND first_activity_at IS NOT NULL;
        IF FOUND THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'erasure activity denied' USING ERRCODE = '42501';
    END IF;
END;
$$;
CREATE FUNCTION public.tracebed_mark_erasure_activity_trigger() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.tracebed_mark_erasure_activity();
    RETURN COALESCE(NEW, OLD);
END;
$$;

DO $$
DECLARE
    cutover_time timestamptz := statement_timestamp();
    key_count bigint;
    trace_count bigint;
    memory_count bigint;
    binding_count bigint;
    backfill_digest bytea;
BEGIN
    WITH key_frames AS (
        SELECT project_id, subject_digest,
               decode('4b', 'hex') || uuid_send(project_id) || subject_digest || uuid_send(key_id)
               || int2send(wrap_version) || CASE WHEN destroyed_at IS NULL THEN decode('00', 'hex') ELSE decode('01', 'hex') END
               || sha256(wrapped_kek) AS frame
          FROM subject_key
    ), trace_frames AS (
        SELECT project_id, run_id, subject_digest,
               decode('54', 'hex') || uuid_send(project_id) || uuid_send(run_id) || subject_digest AS frame
          FROM trace_subject
    ), memory_frames AS (
        SELECT project_id, id, subject_digests,
               decode('4d', 'hex') || uuid_send(project_id) || uuid_send(id)
               || int2send(cardinality(subject_digests)::smallint)
               || COALESCE((
                    SELECT string_agg(digest, ''::bytea ORDER BY ordinality)
                      FROM unnest(memory_item.subject_digests) WITH ORDINALITY AS item(digest, ordinality)
                  ), ''::bytea) AS frame
          FROM memory_item
    ), counts AS (
        SELECT (SELECT count(*) FROM key_frames) AS key_count,
               (SELECT count(*) FROM trace_frames) AS trace_count,
               (SELECT count(*) FROM memory_frames) AS memory_count
    )
    SELECT counts.key_count, counts.trace_count, counts.memory_count
      INTO key_count, trace_count, memory_count
      FROM counts;
    INSERT INTO subject_fence (project_id, subject_digest, first_seen_at)
    SELECT project_id, subject_digest, cutover_time FROM subject_key
    ON CONFLICT DO NOTHING;
    INSERT INTO subject_fence (project_id, subject_digest, first_seen_at)
    SELECT project_id, subject_digest, cutover_time FROM trace_subject
    ON CONFLICT DO NOTHING;
    INSERT INTO subject_fence (project_id, subject_digest, first_seen_at)
    SELECT project_id, item.digest, cutover_time
      FROM memory_item CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
    ON CONFLICT DO NOTHING;
    INSERT INTO subject_fence (project_id, subject_digest, first_seen_at)
    SELECT attributed.project_id, attributed.subject_digest, cutover_time
      FROM (
          SELECT project_id, item.digest AS subject_digest FROM run_owner CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM trace_index CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM outcome_event CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM trace_learning_job CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM injection_log CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM retrieval_event CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM blackboard_entry CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM invalidation_event CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM memory_link CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM derived_state CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM spend_ledger CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM review_queue CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM memory_status_log CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM memory_q_update CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
          UNION SELECT project_id, item.digest FROM killswitch_state CROSS JOIN LATERAL unnest(subject_digests) AS item(digest)
      ) AS attributed
    ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM run_owner ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM trace_index ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM trace_subject ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM outcome_event ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM trace_learning_job ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM injection_log ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM retrieval_event ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM blackboard_entry ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM work_queue WHERE run_id IS NOT NULL ON CONFLICT DO NOTHING;
    INSERT INTO run_fence (project_id, run_id, first_seen_at)
    SELECT project_id, run_id, cutover_time FROM dead_letter WHERE run_id IS NOT NULL ON CONFLICT DO NOTHING;
    INSERT INTO run_memory_binding (project_id, run_id, memory_id, bound_at)
    SELECT job.project_id, job.run_id, memory_id, cutover_time
      FROM trace_learning_job AS job
      CROSS JOIN LATERAL unnest(job.memory_ids) AS item(memory_id)
    ON CONFLICT DO NOTHING;

    -- c11 proposal rows keep their owning run only in bounded JSON
    -- provenance.  Parser/distiller trace arrays and corroboration's bounded
    -- shadow run array are equally authoritative legacy forms.  Bind only a
    -- UUID that resolves to a known same-project run fence; malformed or
    -- foreign selector text remains explicitly project-attributed rather than
    -- being cast/trusted as a new run identity.
    INSERT INTO run_memory_binding (project_id, run_id, memory_id, bound_at)
    SELECT DISTINCT candidate.project_id, candidate.run_id, candidate.memory_id, cutover_time
      FROM (
          SELECT raw_binding.project_id, raw_binding.memory_id,
                 CASE
                     WHEN raw_binding.raw_run_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                     THEN raw_binding.raw_run_id::uuid
                 END AS run_id
            FROM (
                SELECT memory_row.project_id, memory_row.id AS memory_id,
                       memory_row.provenance ->> 'run_id' AS raw_run_id
                  FROM memory_item AS memory_row
                 WHERE memory_row.provenance ->> 'class' = 'proposal'
                UNION ALL
                SELECT memory_row.project_id, memory_row.id,
                       item.value #>> '{}'
                  FROM memory_item AS memory_row
                 CROSS JOIN LATERAL jsonb_array_elements(
                     CASE WHEN jsonb_typeof(memory_row.provenance -> 'trace_ids') = 'array'
                          THEN memory_row.provenance -> 'trace_ids'
                          ELSE '[]'::jsonb END
                 ) AS item(value)
                UNION ALL
                SELECT memory_row.project_id, memory_row.id, confirming_run::text
                  FROM memory_item AS memory_row
                 CROSS JOIN LATERAL unnest(memory_row.shadow_confirm_runs) AS item(confirming_run)
            ) AS raw_binding
      ) AS candidate
      JOIN run_fence AS known_run
        ON known_run.project_id = candidate.project_id
       AND known_run.run_id = candidate.run_id
     WHERE candidate.run_id IS NOT NULL
    ON CONFLICT DO NOTHING;

    -- Normalize every legacy-bound memory from all of its runs before the
    -- cutover receipt is frozen.  Concrete attribution refines the project
    -- sentinel instead of consuming a 65th slot; a direct legacy tag remains
    -- a contributor alongside run provenance.
    WITH candidate_digests AS (
        SELECT memory_row.project_id, memory_row.id AS memory_id, item.digest
          FROM memory_item AS memory_row
         CROSS JOIN LATERAL unnest(memory_row.subject_digests) AS item(digest)
         WHERE item.digest <> public.tracebed_subject_digest(memory_row.project_id, '__project__')
        UNION
        SELECT binding.project_id, binding.memory_id, trace_binding.subject_digest
          FROM run_memory_binding AS binding
          JOIN trace_subject AS trace_binding
            ON trace_binding.project_id = binding.project_id
           AND trace_binding.run_id = binding.run_id
         WHERE trace_binding.subject_digest
               <> public.tracebed_subject_digest(binding.project_id, '__project__')
    ), recomputed AS (
        SELECT memory_row.project_id, memory_row.id,
               COALESCE(
                   array_agg(candidate_digests.digest ORDER BY candidate_digests.digest)
                       FILTER (WHERE candidate_digests.digest IS NOT NULL),
                   ARRAY[public.tracebed_subject_digest(memory_row.project_id, '__project__')]::bytea[]
               ) AS subject_digests
          FROM memory_item AS memory_row
          LEFT JOIN candidate_digests
            ON candidate_digests.project_id = memory_row.project_id
           AND candidate_digests.memory_id = memory_row.id
         GROUP BY memory_row.project_id, memory_row.id
    )
    UPDATE memory_item AS memory_row
       SET subject_digests = recomputed.subject_digests
      FROM recomputed
     WHERE memory_row.project_id = recomputed.project_id
       AND memory_row.id = recomputed.id
       AND memory_row.subject_digests IS DISTINCT FROM recomputed.subject_digests;

    UPDATE memory_link AS link_row
       SET subject_digests = link_row.subject_digests
     WHERE EXISTS (
         SELECT 1 FROM run_memory_binding AS binding
          WHERE binding.project_id = link_row.project_id
            AND binding.memory_id IN (link_row.src_id, link_row.dst_id)
     );
    UPDATE review_queue AS queue_row
       SET subject_digests = queue_row.subject_digests
     WHERE queue_row.memory_id IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM run_memory_binding AS binding
            WHERE binding.project_id = queue_row.project_id
              AND binding.memory_id = queue_row.memory_id
       );
    UPDATE memory_status_log AS log_row
       SET subject_digests = log_row.subject_digests
     WHERE EXISTS (
         SELECT 1 FROM run_memory_binding AS binding
          WHERE binding.project_id = log_row.project_id
            AND binding.memory_id = log_row.memory_id
     );
    UPDATE memory_q_update AS update_row
       SET subject_digests = update_row.subject_digests
     WHERE EXISTS (
         SELECT 1 FROM run_memory_binding AS binding
          WHERE binding.project_id = update_row.project_id
            AND binding.memory_id = update_row.memory_id
     );

    -- The baseline receipt includes both the migrated memory union and the
    -- exact normalized binding set.  Rollback accepts this deterministic
    -- migration-created baseline but rejects even one runtime append.
    WITH key_frames AS (
        SELECT project_id, subject_digest,
               decode('4b', 'hex') || uuid_send(project_id) || subject_digest || uuid_send(key_id)
               || int2send(wrap_version) || CASE WHEN destroyed_at IS NULL THEN decode('00', 'hex') ELSE decode('01', 'hex') END
               || sha256(wrapped_kek) AS frame
          FROM subject_key
    ), trace_frames AS (
        SELECT project_id, run_id, subject_digest,
               decode('54', 'hex') || uuid_send(project_id) || uuid_send(run_id) || subject_digest AS frame
          FROM trace_subject
    ), memory_frames AS (
        SELECT project_id, id, subject_digests,
               decode('4d', 'hex') || uuid_send(project_id) || uuid_send(id)
               || int2send(cardinality(subject_digests)::smallint)
               || COALESCE((
                    SELECT string_agg(digest, ''::bytea ORDER BY ordinality)
                      FROM unnest(memory_item.subject_digests) WITH ORDINALITY AS item(digest, ordinality)
                  ), ''::bytea) AS frame
          FROM memory_item
    ), binding_frames AS (
        SELECT project_id, run_id, memory_id,
               decode('42', 'hex') || uuid_send(project_id) || uuid_send(run_id) || uuid_send(memory_id) AS frame
          FROM run_memory_binding
    ), counts AS (
        SELECT (SELECT count(*) FROM key_frames) AS key_count,
               (SELECT count(*) FROM trace_frames) AS trace_count,
               (SELECT count(*) FROM memory_frames) AS memory_count,
               (SELECT count(*) FROM binding_frames) AS binding_count
    )
    SELECT counts.key_count, counts.trace_count, counts.memory_count, counts.binding_count,
           sha256(
               convert_to('tracebed.erasure-binding-backfill/v2', 'UTF8') || decode('00', 'hex')
               || int8send(counts.key_count)
               || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, subject_digest) FROM key_frames), ''::bytea)
               || int8send(counts.trace_count)
               || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, run_id, subject_digest) FROM trace_frames), ''::bytea)
               || int8send(counts.memory_count)
               || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, id) FROM memory_frames), ''::bytea)
               || int8send(counts.binding_count)
               || COALESCE((SELECT string_agg(sha256(frame), ''::bytea ORDER BY project_id, run_id, memory_id) FROM binding_frames), ''::bytea)
           )
      INTO key_count, trace_count, memory_count, binding_count, backfill_digest
      FROM counts;
    INSERT INTO erasure_cutover_state (
        singleton, cutover_at, ingress_attested_at, legacy_subject_key_rows,
        legacy_trace_subject_rows, legacy_memory_item_rows,
        legacy_run_memory_binding_rows, binding_backfill_digest
    ) VALUES (
        true, cutover_time, cutover_time, key_count, trace_count, memory_count,
        binding_count, backfill_digest
    );
END;
$$;

-- Install only after the deterministic backfill and its singleton receipt
-- exist.  Backfill fence INSERTs are not post-activation work, and a marker
-- must never see a missing singleton half-way through this atomic migration.
CREATE TRIGGER subject_key_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON subject_key
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER trace_subject_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON trace_subject
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER memory_item_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON memory_item
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER outcome_event_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON outcome_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER invalidation_event_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON invalidation_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER trace_learning_job_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON trace_learning_job
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER trace_index_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON trace_index
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER run_owner_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON run_owner
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER work_queue_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON work_queue
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER dead_letter_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON dead_letter
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER memory_link_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON memory_link
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER derived_state_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON derived_state
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER injection_log_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON injection_log
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER retrieval_event_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON retrieval_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER blackboard_entry_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON blackboard_entry
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER spend_ledger_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON spend_ledger
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER review_queue_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON review_queue
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER memory_status_log_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON memory_status_log
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER memory_q_update_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON memory_q_update
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER killswitch_state_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON killswitch_state
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER project_config_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON project_config
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER agent_type_config_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON agent_type_config
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER erasure_request_activity AFTER INSERT OR UPDATE OR DELETE ON erasure_request
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER erasure_step_receipt_activity AFTER INSERT OR UPDATE OR DELETE ON erasure_step_receipt
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER subject_fence_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON subject_fence
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER run_fence_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON run_fence
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER erase_run_set_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON erase_run_set
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER erase_mem_set_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON erase_mem_set
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER run_memory_binding_erasure_activity AFTER INSERT OR UPDATE OR DELETE ON run_memory_binding
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();

-- Read-side companion to the durable write guard below.  Existing runtime
-- roles retain some narrowly-scoped SELECT grants after c11, so a fence must
-- be visible to RLS as well as to endpoint/repository predicates.  Trusted
-- SECURITY DEFINER routines run as ``tracebed_owner`` and must be able to
-- discover a request's complete closure after staging its request row; an
-- ordinary API/worker session never has that current_user identity.
CREATE FUNCTION public.tracebed_erasure_project_is_quiesced(expected_project_id uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- This internal predicate is reached only through profiled SECDEF
    -- admission/closure routines or the invoker RLS wrapper below.  Do not
    -- turn it into a generic owner-less request-state oracle merely because
    -- it returns a boolean rather than a target row.
    IF session_user NOT IN ('tracebed_owner', 'tracebed_api', 'tracebed_worker') THEN
        RAISE EXCEPTION 'erasure project state denied' USING ERRCODE = '42501';
    END IF;
    IF expected_project_id IS NULL
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        -- This helper is intentionally not a project-state oracle.  Every
        -- runtime invocation is bound to the same transaction-local project
        -- GUC used by RLS; callers cannot probe another project's request
        -- state merely because this routine returns a boolean.
        RAISE EXCEPTION 'erasure project state denied' USING ERRCODE = '42501';
    END IF;
    RETURN EXISTS (
        SELECT 1
          FROM public.erasure_request AS request_row
         WHERE request_row.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.disposition <> 'scope_complete')
    );
END;
$$;

CREATE FUNCTION public.tracebed_runtime_erasure_read_allowed(expected_project_id uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- Unlike the small helper above, this wrapper intentionally remains an
    -- invoker function.  RLS needs to distinguish a raw runtime query
    -- (current_user=API/worker) from a trusted SECDEF closure query
    -- (current_user=tracebed_owner); making this wrapper SECDEF would erase
    -- that distinction and leak fenced rows through every policy.
    IF current_user = 'tracebed_owner' THEN
        RETURN true;
    END IF;
    IF expected_project_id IS NULL
       OR current_user IS DISTINCT FROM session_user
       OR session_user NOT IN ('tracebed_api', 'tracebed_worker')
       OR (session_user = 'tracebed_api'
            AND NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member'))
       OR (session_user = 'tracebed_worker'
            AND NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member'))
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RETURN false;
    END IF;
    -- (3) A raw reader must serialize with the exclusive request transaction
    -- before it can obtain even one row.  The ordinary API/worker paths hold
    -- the matching shared ActivityGate for their full disclosure window.
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended(
            'tracebed.erasure.project/v1:' || expected_project_id::text, 0
        )
    );
    RETURN NOT public.tracebed_erasure_project_is_quiesced(expected_project_id);
END;
$$;

-- Keep the established single isolation-policy shape on every pre-E2 parent
-- and leaf.  Updating both sides is required because this catalog models
-- leaf RLS explicitly rather than relying on PostgreSQL partition inheritance.
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
        EXECUTE format(
            'ALTER POLICY %I ON public.%I USING '
            || '(project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid '
            || 'AND public.tracebed_runtime_erasure_read_allowed(project_id)) '
            || 'WITH CHECK (project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid)',
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
            EXECUTE format(
                'ALTER POLICY %I ON public.%I USING '
                || '(project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid '
                || 'AND public.tracebed_runtime_erasure_read_allowed(project_id)) '
                || 'WITH CHECK (project_id = NULLIF(current_setting(''tracebed.project_id'', true), '''')::uuid)',
                leaf_name || '_isolation', leaf_name
            );
        END LOOP;
    END LOOP;
END;
$$;

-- These two queue families are not partitioned, but their residual direct
-- SELECT grants are equally capable of exposing a fenced run.  Their write
-- check intentionally stays project-only so the durable BEFORE trigger below
-- emits P0002 for a raw INSERT instead of an RLS-only denial.
ALTER TABLE public.work_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.work_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY work_queue_erasure_isolation ON public.work_queue
    USING (
        current_user = 'tracebed_owner'
        OR (
            project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid
            AND public.tracebed_runtime_erasure_read_allowed(project_id)
        )
    ) WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
ALTER TABLE public.dead_letter ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dead_letter FORCE ROW LEVEL SECURITY;
CREATE POLICY dead_letter_erasure_isolation ON public.dead_letter
    USING (
        current_user = 'tracebed_owner'
        OR (
            project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid
            AND public.tracebed_runtime_erasure_read_allowed(project_id)
        )
    ) WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
ALTER TABLE public.killswitch_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.killswitch_state FORCE ROW LEVEL SECURITY;
CREATE POLICY killswitch_state_erasure_isolation ON public.killswitch_state
    USING (
        project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid
        AND public.tracebed_runtime_erasure_read_allowed(project_id)
    ) WITH CHECK (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);

-- The application-facing functions take the project shared lock before they
-- touch queue/job/business rows.  This is the matching durable backstop for
-- every residual runtime DML privilege: a compromised or stale API/worker
-- connection cannot use a raw table grant to race an accepted request.  Keep
-- it deliberately project-wide while E2 has no completion phase.  That is the
-- conservative semantics of a nonterminal request and avoids trusting a
-- caller-supplied digest array in a generic trigger.
--
-- A BEFORE ROW trigger can be reached by an accidental direct UPDATE after
-- PostgreSQL has already located a tuple.  It therefore takes the project
-- lock non-blockingly: normal paths acquire the blocking shared lock first in
-- their authority routine, while a raw path fails closed instead of creating
-- a project-lock/tuple-lock inversion with an exclusive request transaction.
CREATE FUNCTION public.tracebed_runtime_erasure_write_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    project_value uuid;
BEGIN
    project_value := CASE WHEN TG_OP = 'DELETE'
        THEN (pg_catalog.to_jsonb(OLD) ->> 'project_id')::uuid
        ELSE (pg_catalog.to_jsonb(NEW) ->> 'project_id')::uuid
    END;
    IF project_value IS NULL THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;

    -- Migration owner activity is authenticated by the c12 lifecycle and
    -- must be able to install/roll back this guard.  Every runtime principal
    -- is checked even when it happens to hold a legacy direct table grant.
    IF session_user = 'tracebed_owner' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    IF session_user NOT IN ('tracebed_api', 'tracebed_worker')
       OR (session_user = 'tracebed_api'
            AND NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member'))
       OR (session_user = 'tracebed_worker'
            AND NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member'))
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM project_value::text
       OR NOT pg_catalog.pg_try_advisory_xact_lock_shared(
            pg_catalog.hashtextextended(
                'tracebed.erasure.project/v1:' || project_value::text, 0
            )
       ) THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;

    -- A project request is a permanent seal; a subject request remains an
    -- E2 nonterminal global quiescence barrier.  Future saga completion must
    -- add a row-specific fence proof before it can relax this condition.
    PERFORM 1
      FROM public.erasure_request AS request_row
     WHERE request_row.project_id = project_value
       AND (request_row.scope = 'project'
            OR request_row.disposition <> 'scope_complete')
     FOR SHARE;
    IF FOUND THEN
        -- The only normal-runtime exception is a certified late subject
        -- association.  The capability row is written only by the profiled
        -- binder in this transaction; raw API/worker DML has neither its
        -- table privilege nor a way to mint this owner-held token.  Keep the
        -- exception to the one digest-only binding row so it cannot become a
        -- generic "write while fenced" escape hatch.
        -- Partition clones expose their concrete child name in
        -- ``TG_TABLE_NAME``.  Check the trusted parent relation as well so
        -- the one certified late-bind insert works on every existing/future
        -- project leaf; a literal parent-name check alone silently rolls the
        -- association back under FORCE RLS.
        IF (
               TG_TABLE_NAME = 'trace_subject'
               OR EXISTS (
                    SELECT 1
                      FROM pg_catalog.pg_inherits AS inheritance
                      JOIN pg_catalog.pg_class AS parent
                        ON parent.oid = inheritance.inhparent
                      JOIN pg_catalog.pg_namespace AS namespace
                        ON namespace.oid = parent.relnamespace
                     WHERE inheritance.inhrelid = TG_RELID
                       AND namespace.nspname = 'public'
                       AND parent.relname = 'trace_subject'
               )
           )
           AND TG_OP IN ('INSERT', 'DELETE')
           -- Refinement may remove only the internal unbound sentinel.  A
           -- late certified bind never gets a generic delete capability.
           AND (
                TG_OP = 'INSERT'
                OR (pg_catalog.to_jsonb(OLD) ->> 'subject_digest')::bytea
                     = public.tracebed_subject_digest(project_value, '__project__')
           )
           AND EXISTS (
                SELECT 1
                  FROM public.erasure_late_bind_capability AS capability
                 WHERE capability.backend_pid = pg_catalog.pg_backend_pid()
                   AND capability.transaction_id = pg_catalog.txid_current()
                   AND capability.project_id = project_value
                   AND capability.run_id = COALESCE(
                       (pg_catalog.to_jsonb(NEW) ->> 'run_id')::uuid,
                       (pg_catalog.to_jsonb(OLD) ->> 'run_id')::uuid
                   )
           ) THEN
            RETURN COALESCE(NEW, OLD);
        END IF;
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

-- Keep this list exhaustive with the E2 durable guard matrix.  The
-- partitioned parents propagate these BEFORE triggers to existing and future
-- project leaves; unpartitioned queue rows are covered explicitly as well.
DROP TRIGGER IF EXISTS ab_run_owner_erasure_write_guard ON run_owner;
CREATE TRIGGER ab_run_owner_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON run_owner
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_work_queue_erasure_write_guard ON work_queue;
CREATE TRIGGER ab_work_queue_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON work_queue
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_dead_letter_erasure_write_guard ON dead_letter;
CREATE TRIGGER ab_dead_letter_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON dead_letter
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_trace_index_erasure_write_guard ON trace_index;
CREATE TRIGGER ab_trace_index_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON trace_index
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_trace_subject_erasure_write_guard ON trace_subject;
CREATE TRIGGER ab_trace_subject_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON trace_subject
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_subject_key_erasure_write_guard ON subject_key;
CREATE TRIGGER ab_subject_key_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON subject_key
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_memory_item_erasure_write_guard ON memory_item;
CREATE TRIGGER ab_memory_item_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON memory_item
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_memory_link_erasure_write_guard ON memory_link;
CREATE TRIGGER ab_memory_link_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON memory_link
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_derived_state_erasure_write_guard ON derived_state;
CREATE TRIGGER ab_derived_state_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON derived_state
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_outcome_event_erasure_write_guard ON outcome_event;
CREATE TRIGGER ab_outcome_event_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON outcome_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_injection_log_erasure_write_guard ON injection_log;
CREATE TRIGGER ab_injection_log_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON injection_log
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_retrieval_event_erasure_write_guard ON retrieval_event;
CREATE TRIGGER ab_retrieval_event_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON retrieval_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_blackboard_entry_erasure_write_guard ON blackboard_entry;
CREATE TRIGGER ab_blackboard_entry_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON blackboard_entry
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_invalidation_event_erasure_write_guard ON invalidation_event;
CREATE TRIGGER ab_invalidation_event_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON invalidation_event
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_spend_ledger_erasure_write_guard ON spend_ledger;
CREATE TRIGGER ab_spend_ledger_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON spend_ledger
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_review_queue_erasure_write_guard ON review_queue;
CREATE TRIGGER ab_review_queue_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON review_queue
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_memory_status_log_erasure_write_guard ON memory_status_log;
CREATE TRIGGER ab_memory_status_log_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON memory_status_log
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_memory_q_update_erasure_write_guard ON memory_q_update;
CREATE TRIGGER ab_memory_q_update_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON memory_q_update
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_trace_learning_job_erasure_write_guard ON trace_learning_job;
CREATE TRIGGER ab_trace_learning_job_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON trace_learning_job
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_killswitch_state_erasure_write_guard ON killswitch_state;
CREATE TRIGGER ab_killswitch_state_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON killswitch_state
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_project_config_erasure_write_guard ON project_config;
CREATE TRIGGER ab_project_config_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON project_config
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_agent_type_config_erasure_write_guard ON agent_type_config;
CREATE TRIGGER ab_agent_type_config_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON agent_type_config
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();
DROP TRIGGER IF EXISTS ab_run_memory_binding_erasure_write_guard ON run_memory_binding;
CREATE TRIGGER ab_run_memory_binding_erasure_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON run_memory_binding
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_runtime_erasure_write_guard();

ALTER TABLE principal_grant DROP CONSTRAINT principal_grant_role_ck;
ALTER TABLE principal_grant ADD CONSTRAINT principal_grant_role_ck
    CHECK (role IN ('admin', 'data', 'export', 'feedback', 'erasure_request'));

CREATE OR REPLACE FUNCTION public.tracebed_require_active_grant(
    expected_project_id uuid, expected_principal_id uuid, expected_agent_type_id uuid,
    expected_grant_id uuid, expected_role text, expected_feedback_source text
) RETURNS TABLE (grant_id uuid, role text, feedback_source text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL OR expected_grant_id IS NULL
       OR expected_role NOT IN ('data', 'feedback', 'admin', 'export', 'erasure_request')
       OR (expected_role = 'feedback' AND (expected_feedback_source IS NULL
           OR expected_feedback_source NOT IN ('verdict', 'correction_adapter', 'downstream')))
       OR (expected_role <> 'feedback' AND expected_feedback_source IS NOT NULL)
       OR pg_catalog.current_setting('tracebed.project_id', true) IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'authority recheck denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM public.authority_admission_state WHERE singleton AND admissions_open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority admission is closed' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT grant_row.grant_id, grant_row.role, grant_row.feedback_source
      FROM public.principal AS principal
      JOIN public.agent_registration AS registration ON registration.principal_id = principal.principal_id
      JOIN public.project AS project ON project.project_id = registration.project_id
      JOIN public.agent_type AS agent_type ON agent_type.agent_type_id = registration.agent_type_id
          AND agent_type.project_id = registration.project_id
      JOIN public.principal_grant AS grant_row ON grant_row.project_id = registration.project_id
          AND grant_row.principal_id = principal.principal_id
     WHERE principal.principal_id = expected_principal_id
       AND registration.project_id = expected_project_id
       AND registration.agent_type_id = expected_agent_type_id
       AND grant_row.grant_id = expected_grant_id
       AND grant_row.role = expected_role
       AND grant_row.feedback_source IS NOT DISTINCT FROM expected_feedback_source
       AND principal.revoked_at IS NULL AND registration.revoked_at IS NULL
       AND project.status = 'active' AND project.deleted_at IS NULL AND grant_row.revoked_at IS NULL
     FOR SHARE OF principal, registration, project, agent_type, grant_row;
END;
$$;

-- E2 publication boundary.  The API has no DML on erasure ledgers/fences;
-- this routine is its one atomic capability.  Lock order is intentionally
-- fixed and repeated by the bind/snapshot routines below: admission/grant,
-- project serialization, sorted run serialization, stable union, subject
-- fence, run fence, then business closure rows.  Do not introduce a
-- subject-before-run path elsewhere.
CREATE FUNCTION public.tracebed_request_erasure(
    expected_project_id uuid,
    expected_principal_id uuid,
    expected_agent_type_id uuid,
    expected_grant_id uuid,
    requested_scope text,
    raw_subject_tag text
) RETURNS TABLE (
    request_id uuid,
    scope text,
    phase text,
    disposition text,
    last_code text,
    limitation_codes text[],
    requested_at timestamptz,
    updated_at timestamptz,
    completed_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    target_digest bytea;
    inserted_request_id uuid;
    existing_state text;
    existing_request_id uuid;
    run_value uuid;
    run_ids uuid[];
    closure_digests bytea[];
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL OR expected_grant_id IS NULL
       OR requested_scope NOT IN ('subject', 'project')
       OR (requested_scope = 'subject' AND (
               raw_subject_tag IS NULL
               OR NOT public.tracebed_subject_tag_is_valid(raw_subject_tag, false)
           ))
       OR (requested_scope = 'project' AND raw_subject_tag IS NOT NULL)
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'erasure request denied' USING ERRCODE = '42501';
    END IF;

    -- (2) admission/active grant authority.  It holds the admission SHARE
    -- tuple lock through this transaction and checks exact actor/grant facts.
    PERFORM 1
      FROM public.tracebed_require_active_grant(
          expected_project_id, expected_principal_id, expected_agent_type_id,
          expected_grant_id, 'erasure_request', NULL
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'erasure request denied' USING ERRCODE = '42501';
    END IF;

    IF requested_scope = 'subject' THEN
        target_digest := public.tracebed_subject_digest(expected_project_id, raw_subject_tag);
    ELSE
        target_digest := NULL;
    END IF;

    -- (3) serialize target/replay decisions per project before observing any
    -- closure.  Every ordinary bind/guard uses the shared counterpart.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'tracebed.erasure.project/v1:' || expected_project_id::text, 0
        )
    );

    -- Exact replay wins before the one-active-project conflict check.  It
    -- never rewrites actor attribution or target identity.
    RETURN QUERY
    SELECT request_row.request_id, request_row.scope, request_row.phase,
           request_row.disposition, request_row.last_code,
           request_row.limitation_codes, request_row.requested_at,
           request_row.updated_at, request_row.completed_at
      FROM public.erasure_request AS request_row
     WHERE request_row.project_id = expected_project_id
       AND request_row.scope = requested_scope
       AND request_row.subject_digest IS NOT DISTINCT FROM target_digest
     FOR UPDATE;
    IF FOUND THEN
        RETURN;
    END IF;

    -- A project request is a permanent seal, not merely an active-worker
    -- claim.  The exact project replay returned above; any other target is
    -- deliberately one opaque conflict regardless of its state/identity.
    IF EXISTS (
        SELECT 1 FROM public.erasure_request AS request_row
         WHERE request_row.project_id = expected_project_id
           AND request_row.scope = 'project'
    ) OR EXISTS (
        SELECT 1 FROM public.erasure_request AS request_row
         WHERE request_row.project_id = expected_project_id
           AND request_row.disposition <> 'scope_complete'
    ) THEN
        RAISE EXCEPTION 'erasure target conflict' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO public.erasure_request (
        project_id, scope, subject_digest, requested_principal_id,
        requested_agent_type_id, requested_grant_id, requested_by_session
    ) VALUES (
        expected_project_id, requested_scope, target_digest, expected_principal_id,
        expected_agent_type_id, expected_grant_id, session_user
    ) RETURNING public.erasure_request.request_id INTO inserted_request_id;

    -- (4) sorted run-level serialization.  The project request captures all
    -- durable run-bearing rows; a subject request starts from every current
    -- digest-attributed row.  Re-read after locks before fencing.
    SELECT COALESCE(array_agg(candidate.run_id ORDER BY candidate.run_id), '{}'::uuid[])
      INTO run_ids
      FROM (
          SELECT owner_row.run_id FROM public.run_owner AS owner_row
           WHERE owner_row.project_id = expected_project_id
             AND (requested_scope = 'project' OR owner_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT trace_row.run_id FROM public.trace_index AS trace_row
           WHERE trace_row.project_id = expected_project_id
             AND (requested_scope = 'project' OR trace_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT binding.run_id FROM public.trace_subject AS binding
           WHERE binding.project_id = expected_project_id
             AND (requested_scope = 'project' OR binding.subject_digest = target_digest)
          UNION
          SELECT outcome_row.run_id FROM public.outcome_event AS outcome_row
           WHERE outcome_row.project_id = expected_project_id
             AND (requested_scope = 'project' OR outcome_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT job_row.run_id FROM public.trace_learning_job AS job_row
           WHERE job_row.project_id = expected_project_id
             AND (requested_scope = 'project' OR job_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT retrieval_row.run_id FROM public.retrieval_event AS retrieval_row
           WHERE retrieval_row.project_id = expected_project_id
             AND (requested_scope = 'project' OR retrieval_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT injection_row.run_id FROM public.injection_log AS injection_row
           WHERE injection_row.project_id = expected_project_id
             AND (requested_scope = 'project' OR injection_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT entry_row.run_id FROM public.blackboard_entry AS entry_row
           WHERE entry_row.project_id = expected_project_id
             AND (requested_scope = 'project' OR entry_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT binding.run_id FROM public.run_memory_binding AS binding
          JOIN public.memory_item AS memory_row
            ON memory_row.project_id = binding.project_id AND memory_row.id = binding.memory_id
           WHERE binding.project_id = expected_project_id
             AND (requested_scope = 'project' OR memory_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT queue_row.run_id FROM public.work_queue AS queue_row
           WHERE queue_row.project_id = expected_project_id AND queue_row.run_id IS NOT NULL
             AND (requested_scope = 'project' OR queue_row.subject_digests @> ARRAY[target_digest]::bytea[])
          UNION
          SELECT dead_row.run_id FROM public.dead_letter AS dead_row
           WHERE dead_row.project_id = expected_project_id AND dead_row.run_id IS NOT NULL
             AND (requested_scope = 'project' OR dead_row.subject_digests @> ARRAY[target_digest]::bytea[])
      ) AS candidate;
    FOREACH run_value IN ARRAY run_ids LOOP
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended(
                'tracebed.erasure.run/v1:' || expected_project_id::text || ':' || run_value::text,
                0
            )
        );
        -- A run owner is the durable run-level row where one exists.  The
        -- advisory lock covers historical rows that predate an owner binding.
        PERFORM 1 FROM public.run_owner AS owner_row
         WHERE owner_row.project_id = expected_project_id AND owner_row.run_id = run_value
         FOR UPDATE;
    END LOOP;

    -- (5) derive one stable authoritative run-subject union after *every*
    -- run lock.  The request target is included even when it has no current
    -- run, so the next step always has one canonical sorted fence set.
    -- Never shortcut this to the target alone: that would mix a target-only
    -- subject->run path with bind/snapshot's run->stable-union->subjects
    -- protocol and re-open a deadlock/race surface.
    SELECT COALESCE(array_agg(DISTINCT digest ORDER BY digest), '{}'::bytea[])
      INTO closure_digests
      FROM (
          SELECT binding.subject_digest AS digest
            FROM public.trace_subject AS binding
           WHERE binding.project_id = expected_project_id
             AND binding.run_id = ANY(run_ids)
          UNION
          SELECT target_digest
           WHERE requested_scope = 'subject'
      ) AS closure_union;

    -- (6) ensure then lock all known subject fences in bytewise canonical
    -- order before a run fence can be read or changed.  Non-target fences
    -- remain live for a subject request; they are lock witnesses for the
    -- stable-union proof, not additional erase targets.
    INSERT INTO public.subject_fence (project_id, subject_digest)
    SELECT expected_project_id, digest
      FROM unnest(closure_digests) AS item(digest)
    ON CONFLICT (project_id, subject_digest) DO NOTHING;
    PERFORM 1 FROM public.subject_fence AS fence
     WHERE fence.project_id = expected_project_id
       AND fence.subject_digest = ANY(closure_digests)
     ORDER BY fence.subject_digest
     FOR UPDATE;

    IF requested_scope = 'subject' THEN
        SELECT fence.state, fence.request_id
          INTO existing_state, existing_request_id
          FROM public.subject_fence AS fence
         WHERE fence.project_id = expected_project_id AND fence.subject_digest = target_digest
         FOR UPDATE;
        IF existing_state IS DISTINCT FROM 'live' THEN
            -- An exact request row would have returned above.  Any remaining
            -- non-live fence is corrupt/foreign authority and must not be
            -- attached or disclosed by this request.
            RAISE EXCEPTION 'erasure target conflict' USING ERRCODE = 'P0001';
        END IF;
        UPDATE public.subject_fence
           SET state = 'fenced', request_id = inserted_request_id,
               fenced_at = statement_timestamp()
         WHERE project_id = expected_project_id AND subject_digest = target_digest;
    END IF;

    -- (7) create/assert and fence every discovered run after the subject
    -- fence.  ``erase_run_set`` is append-only closure evidence.
    FOREACH run_value IN ARRAY run_ids LOOP
        INSERT INTO public.run_fence (project_id, run_id)
        VALUES (expected_project_id, run_value)
        ON CONFLICT (project_id, run_id) DO NOTHING;
        SELECT fence.state, fence.request_id
          INTO existing_state, existing_request_id
          FROM public.run_fence AS fence
         WHERE fence.project_id = expected_project_id AND fence.run_id = run_value
         FOR UPDATE;
        IF existing_state IS DISTINCT FROM 'live' THEN
            RAISE EXCEPTION 'erasure target conflict' USING ERRCODE = 'P0001';
        END IF;
        INSERT INTO public.erase_run_set (project_id, request_id, run_id)
        VALUES (expected_project_id, inserted_request_id, run_value)
        -- ``request_id`` is also this function's RETURNS TABLE output
        -- variable.  Name the physical key instead of an unqualified column
        -- list so PL/pgSQL cannot resolve it as the output variable.
        ON CONFLICT ON CONSTRAINT erase_run_set_pkey DO NOTHING;
        UPDATE public.run_fence
           SET state = 'fenced', request_id = inserted_request_id,
               fenced_at = statement_timestamp()
         WHERE project_id = expected_project_id AND run_id = run_value;
    END LOOP;

    -- (10) A depth cap is a refusal boundary, never a truncation rule.  Probe
    -- the next edge at depth 1024 before writing any closure row: accepting a
    -- partial graph would make the returned 202 falsely claim a durable
    -- fence over memory that remains reachable past the cap.
    IF EXISTS (
        WITH RECURSIVE closure(memory_id, closure_depth, path) AS (
            SELECT memory_row.id, 0, ARRAY[memory_row.id]
              FROM public.memory_item AS memory_row
             WHERE memory_row.project_id = expected_project_id
               AND (requested_scope = 'project'
                    OR memory_row.subject_digests @> ARRAY[target_digest]::bytea[]
                    OR EXISTS (
                        SELECT 1 FROM public.run_memory_binding AS run_memory
                         WHERE run_memory.project_id = expected_project_id
                           AND run_memory.memory_id = memory_row.id
                           AND run_memory.run_id = ANY(run_ids)
                    ))
            UNION ALL
            SELECT CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END,
                   closure.closure_depth + 1,
                   closure.path || CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
              FROM closure
              JOIN public.memory_link AS link
                ON link.project_id = expected_project_id
               AND (link.src_id = closure.memory_id OR link.dst_id = closure.memory_id)
             WHERE closure.closure_depth < 1024
               AND NOT (CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
                        = ANY(closure.path))
        )
        SELECT 1
          FROM closure
          JOIN public.memory_link AS next_link
            ON next_link.project_id = expected_project_id
           AND (next_link.src_id = closure.memory_id OR next_link.dst_id = closure.memory_id)
         WHERE closure.closure_depth = 1024
           AND NOT (CASE WHEN next_link.src_id = closure.memory_id
                         THEN next_link.dst_id ELSE next_link.src_id END = ANY(closure.path))
         LIMIT 1
    ) THEN
        RAISE EXCEPTION 'erasure closure exceeds bounded depth' USING ERRCODE = 'P0005';
    END IF;

    -- Capture direct and transitive memory closure under the same transaction
    -- only after the bounded proof above has succeeded.
    INSERT INTO public.erase_mem_set (project_id, request_id, memory_id, closure_depth)
    WITH RECURSIVE closure(memory_id, closure_depth, path) AS (
        SELECT memory_row.id, 0, ARRAY[memory_row.id]
          FROM public.memory_item AS memory_row
         WHERE memory_row.project_id = expected_project_id
           AND (requested_scope = 'project'
                OR memory_row.subject_digests @> ARRAY[target_digest]::bytea[]
                -- A multi-subject memory may carry a union that does not
                -- itself include this target after historical attribution
                -- repair. Its normalized run binding is still authoritative
                -- closure evidence and must be captured with the fenced run.
                OR EXISTS (
                    SELECT 1 FROM public.run_memory_binding AS run_memory
                     WHERE run_memory.project_id = expected_project_id
                       AND run_memory.memory_id = memory_row.id
                       AND run_memory.run_id = ANY(run_ids)
                ))
        UNION ALL
        SELECT CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END,
               closure.closure_depth + 1,
               closure.path || CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
          FROM closure
          JOIN public.memory_link AS link
            ON link.project_id = expected_project_id
           AND (link.src_id = closure.memory_id OR link.dst_id = closure.memory_id)
         WHERE closure.closure_depth < 1024
           AND NOT (CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
                    = ANY(closure.path))
    )
    SELECT expected_project_id, inserted_request_id, closure.memory_id,
           min(closure.closure_depth)
      FROM closure
     GROUP BY closure.memory_id
    -- See the erase_run_set insert above: use the physical key name to keep
    -- the public ``request_id`` return column out of SQL name resolution.
    ON CONFLICT ON CONSTRAINT erase_mem_set_pkey DO NOTHING;

    UPDATE public.erasure_request AS request_row
       SET phase = 'fenced', disposition = 'active', last_code = 'fenced',
           limitation_codes = ARRAY[
               'backups', 'external_systems', 'legacy_v1_metadata',
               'operational_logs', 'unbound_data'
           ]::text[],
           updated_at = GREATEST(
               pg_catalog.clock_timestamp(),
               request_row.requested_at + interval '1 microsecond'
           )
     WHERE request_row.project_id = expected_project_id
       AND request_row.request_id = inserted_request_id;

    RETURN QUERY
    SELECT request_row.request_id, request_row.scope, request_row.phase,
           request_row.disposition, request_row.last_code,
           request_row.limitation_codes, request_row.requested_at,
           request_row.updated_at, request_row.completed_at
      FROM public.erasure_request AS request_row
     WHERE request_row.project_id = expected_project_id
       AND request_row.request_id = inserted_request_id;
END;
$$;

CREATE FUNCTION public.tracebed_erasure_request_status(
    expected_project_id uuid,
    expected_principal_id uuid,
    expected_agent_type_id uuid,
    expected_grant_id uuid,
    expected_request_id uuid
) RETURNS TABLE (
    request_id uuid,
    scope text,
    phase text,
    disposition text,
    last_code text,
    limitation_codes text[],
    requested_at timestamptz,
    updated_at timestamptz,
    completed_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL OR expected_grant_id IS NULL
       OR expected_request_id IS NULL
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'erasure status denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1
      FROM public.tracebed_require_active_grant(
          expected_project_id, expected_principal_id, expected_agent_type_id,
          expected_grant_id, 'erasure_request', NULL
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'erasure status denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT request_row.request_id, request_row.scope, request_row.phase,
           request_row.disposition, request_row.last_code,
           request_row.limitation_codes, request_row.requested_at,
           request_row.updated_at, request_row.completed_at
      FROM public.erasure_request AS request_row
     WHERE request_row.project_id = expected_project_id
       AND request_row.request_id = expected_request_id;
END;
$$;

-- API-only atomic run opening.  A run owner and its live fence are one
-- admission fact: a caller never receives a writable run whose fence was
-- created later by a separate, bypassable repository call.
CREATE FUNCTION public.tracebed_open_erasure_guarded_run(
    expected_project_id uuid,
    expected_principal_id uuid,
    expected_agent_type_id uuid,
    expected_grant_id uuid,
    expected_run_id uuid,
    expected_origin text
) RETURNS TABLE (writable boolean, late_bind_eligible boolean, origin text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    owner_principal_id uuid;
    owner_agent_type_id uuid;
    owner_origin text;
    fence_state text;
    active_scope text;
    has_live_fence boolean := false;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL OR expected_grant_id IS NULL OR expected_run_id IS NULL
       OR expected_origin NOT IN ('retrieve', 'trace')
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'run opening denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM public.tracebed_require_active_grant(
        expected_project_id, expected_principal_id, expected_agent_type_id,
        expected_grant_id, 'data', NULL
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'run opening denied' USING ERRCODE = '42501';
    END IF;

    -- Fixed order: grant/admission, project shared serialization, then this
    -- one run's exclusive serialization before inspecting its durable rows.
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || expected_project_id::text, 0)
    );
    SELECT request_row.scope INTO active_scope
      FROM public.erasure_request AS request_row
     WHERE request_row.project_id = expected_project_id
       AND (request_row.scope = 'project' OR request_row.disposition <> 'scope_complete')
     ORDER BY request_row.requested_at, request_row.request_id
     LIMIT 1
     FOR SHARE;
    -- A project request seals all ingress.  A subject request has one narrow
    -- containment exception below: an already-owned *live* run may reach the
    -- binder solely to attach a newly discovered target and fence its closure.
    -- It is never business-writable and no request may create a new run here.
    IF FOUND AND active_scope = 'project' THEN
        RETURN QUERY SELECT false, false, NULL::text;
        RETURN;
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'tracebed.erasure.run/v1:' || expected_project_id::text || ':' || expected_run_id::text,
            0
        )
    );

    -- Do not lock run_fence here.  The authoritative binder takes the
    -- canonical subject-fence locks before its run-fence lock; taking the
    -- latter in this opener would invert that order for a late bind.  The
    -- run advisory plus project shared serialization stabilise eligibility,
    -- and the binder re-reads/locks the durable row before any propagation.
    SELECT fence.state INTO fence_state
      FROM public.run_fence AS fence
     WHERE fence.project_id = expected_project_id AND fence.run_id = expected_run_id;
    has_live_fence := FOUND AND fence_state = 'live';
    IF FOUND AND NOT has_live_fence THEN
        RETURN QUERY SELECT false, false, NULL::text;
        RETURN;
    END IF;

    SELECT owner_row.principal_id, owner_row.agent_type_id, owner_row.origin
      INTO owner_principal_id, owner_agent_type_id, owner_origin
      FROM public.run_owner AS owner_row
     WHERE owner_row.project_id = expected_project_id AND owner_row.run_id = expected_run_id
     FOR UPDATE;
    IF FOUND THEN
        IF owner_principal_id IS DISTINCT FROM expected_principal_id
           OR owner_agent_type_id IS DISTINCT FROM expected_agent_type_id THEN
            RAISE EXCEPTION 'run authority denied' USING ERRCODE = 'P0002';
        END IF;
        IF active_scope = 'subject' THEN
            -- Do not let an active subject request create/revive a fence.  A
            -- pre-existing same-owner live run is merely eligible for the
            -- next bind call to record the target association/closure.
            RETURN QUERY SELECT false, has_live_fence, owner_origin;
            RETURN;
        END IF;
    ELSE
        IF active_scope = 'subject' THEN
            RETURN QUERY SELECT false, false, NULL::text;
            RETURN;
        END IF;
        INSERT INTO public.run_owner (
            project_id, run_id, principal_id, agent_type_id, origin, bound_at
        ) VALUES (
            expected_project_id, expected_run_id, expected_principal_id,
            expected_agent_type_id, expected_origin, statement_timestamp()
        );
    END IF;
    INSERT INTO public.run_fence (project_id, run_id)
    VALUES (expected_project_id, expected_run_id)
    ON CONFLICT (project_id, run_id) DO NOTHING;
    RETURN QUERY SELECT true, false, COALESCE(owner_origin, expected_origin);
END;
$$;

-- Bind only opaque tags to a durable run.  New ``trace_subject`` rows are
-- digest-only; a raw tag is validated and hashed inside this function and is
-- never persisted, logged, or returned.
CREATE FUNCTION public.tracebed_bind_run_subject_tags(
    expected_project_id uuid,
    expected_principal_id uuid,
    expected_agent_type_id uuid,
    expected_grant_id uuid,
    expected_run_id uuid,
    expected_role text,
    raw_subject_tags text[]
) RETURNS TABLE (subject_digests bytea[], writable boolean, blocking_request_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    supplied_digests bytea[];
    full_digests bytea[];
    owner_principal_id uuid;
    owner_agent_type_id uuid;
    run_state text;
    run_request_id uuid;
    blocking_request uuid;
    active_scope text;
    active_target_digest bytea;
    active_feedback_source text;
    too_many boolean := false;
    late_new_run_ids uuid[] := '{}'::uuid[];
    late_new_mem_ids uuid[] := '{}'::uuid[];
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL OR expected_grant_id IS NULL OR expected_run_id IS NULL
       OR expected_role NOT IN ('data', 'feedback')
       OR raw_subject_tags IS NULL
       OR (pg_catalog.cardinality(raw_subject_tags) <> 0
           AND pg_catalog.array_ndims(raw_subject_tags) IS DISTINCT FROM 1)
       OR pg_catalog.cardinality(raw_subject_tags) > 64
       OR pg_catalog.array_position(raw_subject_tags, NULL::text) IS NOT NULL
       OR (expected_role = 'feedback' AND pg_catalog.cardinality(raw_subject_tags) <> 0)
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'run subject binding denied' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (
        SELECT 1 FROM unnest(raw_subject_tags) AS tag
         WHERE NOT public.tracebed_subject_tag_is_valid(tag, false)
    ) OR (SELECT count(*) FROM unnest(raw_subject_tags))
          IS DISTINCT FROM (SELECT count(DISTINCT tag COLLATE "C") FROM unnest(raw_subject_tags) AS tag) THEN
        RAISE EXCEPTION 'run subject binding denied' USING ERRCODE = '42501';
    END IF;
    -- The public bind signature deliberately carries no caller-supplied
    -- feedback-source selector.  For a feedback-owned outcome, derive the
    -- bounded source from the exact durable grant first; the authoritative
    -- helper below then locks/rechecks the complete project/principal/agent/
    -- grant tuple against that derived value.  A foreign/revoked/mismatched
    -- grant never reaches a successful bind and no source is returned.
    IF expected_role = 'feedback' THEN
        SELECT grant_row.feedback_source INTO active_feedback_source
          FROM public.principal_grant AS grant_row
         WHERE grant_row.grant_id = expected_grant_id;
        IF active_feedback_source NOT IN ('verdict', 'correction_adapter', 'downstream') THEN
            RAISE EXCEPTION 'run subject binding denied' USING ERRCODE = '42501';
        END IF;
    END IF;
    PERFORM 1 FROM public.tracebed_require_active_grant(
        expected_project_id, expected_principal_id, expected_agent_type_id,
        expected_grant_id, expected_role, active_feedback_source
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'run subject binding denied' USING ERRCODE = '42501';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || expected_project_id::text, 0)
    );
    SELECT request_row.request_id, request_row.scope, request_row.subject_digest
      INTO blocking_request, active_scope, active_target_digest
      FROM public.erasure_request AS request_row
     WHERE request_row.project_id = expected_project_id
       AND (request_row.scope = 'project' OR request_row.disposition <> 'scope_complete')
     ORDER BY request_row.requested_at, request_row.request_id
     LIMIT 1
     FOR SHARE;
    IF FOUND AND active_scope = 'project' THEN
        RETURN QUERY SELECT '{}'::bytea[], false, NULL::uuid;
        RETURN;
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'tracebed.erasure.run/v1:' || expected_project_id::text || ':' || expected_run_id::text,
            0
        )
    );
    SELECT owner_row.principal_id, owner_row.agent_type_id
      INTO owner_principal_id, owner_agent_type_id
      FROM public.run_owner AS owner_row
     WHERE owner_row.project_id = expected_project_id AND owner_row.run_id = expected_run_id
     FOR UPDATE;
    IF NOT FOUND OR (expected_role = 'data' AND (
           owner_principal_id IS DISTINCT FROM expected_principal_id
           OR owner_agent_type_id IS DISTINCT FROM expected_agent_type_id
       )) THEN
        RAISE EXCEPTION 'run authority denied' USING ERRCODE = 'P0002';
    END IF;

    SELECT COALESCE(array_agg(public.tracebed_subject_digest(expected_project_id, tag) ORDER BY
                              public.tracebed_subject_digest(expected_project_id, tag)), '{}'::bytea[])
      INTO supplied_digests
      FROM unnest(raw_subject_tags) AS tag;
    IF pg_catalog.cardinality(supplied_digests) IS DISTINCT FROM
       (SELECT count(DISTINCT digest)
          FROM unnest(supplied_digests) AS item(digest)) THEN
        RAISE EXCEPTION 'run subject binding denied' USING ERRCODE = '42501';
    END IF;
    -- An untagged run is explicitly project-attributed.  It is never an
    -- empty/unknown union: queue snapshots, run-owner attribution and the
    -- durable trace_subject union must all name the same internal sentinel.
    -- The project sentinel is an unbound fallback, never a 65th concrete
    -- identity.  Refine it away atomically as soon as a real tag arrives so
    -- retrieval/outcome-first and trace-first runs have the same 64-tag
    -- admission result.
    WITH candidates AS (
        SELECT binding.subject_digest AS digest
          FROM public.trace_subject AS binding
         WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id
        UNION
        SELECT digest FROM unnest(supplied_digests) AS item(digest)
    ), concrete AS (
        SELECT digest
          FROM candidates
         WHERE digest <> public.tracebed_subject_digest(expected_project_id, '__project__')
    )
    SELECT COALESCE(
               array_agg(digest ORDER BY digest),
               ARRAY[public.tracebed_subject_digest(expected_project_id, '__project__')]::bytea[]
           )
      INTO full_digests
      FROM concrete;
    too_many := pg_catalog.cardinality(full_digests) > 64;

    -- A subject request normally quiesces all ingress.  The sole exception
    -- is a late association to its already-fenced subject: it must be
    -- durably attached to the request so the closure cannot be bypassed.
    -- A different subject remains a pure refusal with no business write.
    IF active_scope = 'subject'
       AND NOT (active_target_digest = ANY(full_digests)) THEN
        RETURN QUERY SELECT full_digests, false, NULL::uuid;
        RETURN;
    END IF;

    -- (6) ensure/lock subject fences in digest order after a stable union.
    -- A live row is created only for a capacity-valid union; a late target
    -- association sees its existing non-live row without reviving it.
    -- A live run may receive normal monotone propagation.  A late target
    -- association is closure evidence only: it is committed below, fenced,
    -- and never gets to enqueue or resume ordinary business work.
    IF NOT too_many AND blocking_request IS NULL THEN
        INSERT INTO public.subject_fence (project_id, subject_digest)
        SELECT expected_project_id, digest FROM unnest(full_digests) AS item(digest)
        ON CONFLICT (project_id, subject_digest) DO NOTHING;
    END IF;
    PERFORM 1 FROM public.subject_fence AS fence
     WHERE fence.project_id = expected_project_id
       AND fence.subject_digest = ANY(full_digests)
     ORDER BY fence.subject_digest
     FOR UPDATE;
    SELECT fence.request_id
      INTO blocking_request
      FROM public.subject_fence AS fence
     WHERE fence.project_id = expected_project_id
       AND fence.subject_digest = ANY(full_digests)
       AND fence.state <> 'live'
     ORDER BY fence.subject_digest
     LIMIT 1;
    IF (SELECT count(DISTINCT fence.request_id)
          FROM public.subject_fence AS fence
         WHERE fence.project_id = expected_project_id
           AND fence.subject_digest = ANY(full_digests)
           AND fence.state <> 'live') > 1 THEN
        RAISE EXCEPTION 'erasure fence state is inconsistent' USING ERRCODE = 'P0002';
    END IF;

    -- (7) assert/lock the run fence after subject fences.  A late binding
    -- must attach its run to the same request rather than merely rolling back
    -- and leaving a new association invisible to the requester closure.
    INSERT INTO public.run_fence (project_id, run_id)
    VALUES (expected_project_id, expected_run_id)
    ON CONFLICT (project_id, run_id) DO NOTHING;
    SELECT fence.state, fence.request_id INTO run_state, run_request_id
      FROM public.run_fence AS fence
     WHERE fence.project_id = expected_project_id AND fence.run_id = expected_run_id
     FOR UPDATE;
    IF run_state IS DISTINCT FROM 'live' THEN
        IF blocking_request IS NULL THEN
            blocking_request := run_request_id;
        ELSIF run_request_id IS DISTINCT FROM blocking_request THEN
            RAISE EXCEPTION 'erasure fence state is inconsistent' USING ERRCODE = 'P0002';
        END IF;
    END IF;
    IF too_many AND blocking_request IS NULL THEN
        RAISE EXCEPTION 'run subject capacity denied' USING ERRCODE = 'P0004';
    END IF;

    -- Any non-live subject/run blocks business work.  The late path records
    -- only closure evidence below; it must not run the ordinary propagation
    -- UPDATEs while the project request is active.
    IF NOT too_many THEN
        IF EXISTS (
            WITH affected_memory AS (
                SELECT binding.memory_id
                  FROM public.run_memory_binding AS binding
                 WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id
            ), proposed AS (
                SELECT affected_memory.memory_id, digest
                  FROM affected_memory CROSS JOIN LATERAL unnest(full_digests) AS item(digest)
                UNION
                SELECT binding.memory_id, trace_binding.subject_digest
                  FROM public.run_memory_binding AS binding
                  JOIN public.trace_subject AS trace_binding
                    ON trace_binding.project_id = binding.project_id
                   AND trace_binding.run_id = binding.run_id
                 WHERE binding.project_id = expected_project_id
                   AND binding.memory_id IN (SELECT memory_id FROM affected_memory)
                   AND binding.run_id <> expected_run_id
                   AND trace_binding.subject_digest
                       <> public.tracebed_subject_digest(expected_project_id, '__project__')
            )
            SELECT 1 FROM proposed GROUP BY memory_id HAVING count(DISTINCT digest) > 64
        ) THEN
            IF blocking_request IS NULL THEN
                RAISE EXCEPTION 'run memory attribution capacity denied' USING ERRCODE = 'P0004';
            END IF;
            too_many := true;
        END IF;
    END IF;

    IF NOT too_many AND blocking_request IS NULL THEN
        INSERT INTO public.trace_subject (project_id, run_id, subject_tag, subject_digest)
        SELECT expected_project_id, expected_run_id, NULL, digest
          FROM unnest(full_digests) AS item(digest)
        ON CONFLICT (project_id, run_id, subject_digest) DO NOTHING;
        -- A formerly untagged run gets a concrete canonical union.  Delete
        -- only the sentinel after the concrete rows are durable; the normal
        -- path has no active request and the late path uses the certified
        -- capability below.
        DELETE FROM public.trace_subject AS binding
         WHERE binding.project_id = expected_project_id
           AND binding.run_id = expected_run_id
           AND binding.subject_digest = public.tracebed_subject_digest(
               expected_project_id, '__project__'
           )
           AND EXISTS (
               SELECT 1 FROM unnest(full_digests) AS item(digest)
                WHERE digest <> public.tracebed_subject_digest(expected_project_id, '__project__')
           );

        -- (8) queue/job rows receive the complete post-bind union, including
        -- leased/dead rows.  Attribution is monotone and does not affect a
        -- replay identity.
        UPDATE public.work_queue AS queue_row
           SET subject_digests = full_digests
         WHERE queue_row.project_id = expected_project_id AND queue_row.run_id = expected_run_id;
        UPDATE public.dead_letter AS dead_row
           SET subject_digests = full_digests
         WHERE dead_row.project_id = expected_project_id AND dead_row.run_id = expected_run_id;
        UPDATE public.outcome_event AS outcome_row
           SET subject_digests = full_digests
         WHERE outcome_row.project_id = expected_project_id AND outcome_row.run_id = expected_run_id;
        UPDATE public.trace_learning_job AS job_row
           SET subject_digests = full_digests
         WHERE job_row.project_id = expected_project_id AND job_row.run_id = expected_run_id;
        UPDATE public.run_owner AS owner_row
           SET subject_digests = full_digests
         WHERE owner_row.project_id = expected_project_id AND owner_row.run_id = expected_run_id;
        UPDATE public.trace_index AS index_row
           SET subject_digests = full_digests
         WHERE index_row.project_id = expected_project_id AND index_row.run_id = expected_run_id;
        UPDATE public.injection_log AS injection_row
           SET subject_digests = full_digests
         WHERE injection_row.project_id = expected_project_id AND injection_row.run_id = expected_run_id;
        UPDATE public.retrieval_event AS retrieval_row
           SET subject_digests = full_digests
         WHERE retrieval_row.project_id = expected_project_id AND retrieval_row.run_id = expected_run_id;
        UPDATE public.blackboard_entry AS entry_row
           SET subject_digests = full_digests
         WHERE entry_row.project_id = expected_project_id AND entry_row.run_id = expected_run_id;

        -- (10) Recompute each linked memory from every normalized run binding
        -- rather than overwriting a multi-run memory's other attribution.
        UPDATE public.memory_item AS memory_row
           SET subject_digests = computed.digests
          FROM (
              SELECT binding.memory_id,
                     COALESCE(
                         array_agg(DISTINCT trace_binding.subject_digest
                                   ORDER BY trace_binding.subject_digest)
                           FILTER (
                               WHERE trace_binding.subject_digest
                                     <> public.tracebed_subject_digest(expected_project_id, '__project__')
                           ),
                         ARRAY[public.tracebed_subject_digest(expected_project_id, '__project__')]::bytea[]
                     ) AS digests
                FROM public.run_memory_binding AS binding
                JOIN public.trace_subject AS trace_binding
                  ON trace_binding.project_id = binding.project_id
                 AND trace_binding.run_id = binding.run_id
               WHERE binding.project_id = expected_project_id
                 AND binding.memory_id IN (
                     SELECT affected.memory_id FROM public.run_memory_binding AS affected
                      WHERE affected.project_id = expected_project_id
                        AND affected.run_id = expected_run_id
                 )
               GROUP BY binding.memory_id
          ) AS computed
         WHERE memory_row.project_id = expected_project_id
           AND memory_row.id = computed.memory_id;

        -- Any memory-derived disclosure/ledger row is recomputed in the
        -- same bind transaction.  These updates intentionally assign the
        -- current value: the BEFORE guards replace it with the canonical
        -- linked-memory union while preserving an explicitly empty union.
        UPDATE public.memory_link AS link_row
           SET subject_digests = link_row.subject_digests
         WHERE link_row.project_id = expected_project_id
           AND (link_row.src_id IN (
                   SELECT binding.memory_id FROM public.run_memory_binding AS binding
                    WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id
               ) OR link_row.dst_id IN (
                   SELECT binding.memory_id FROM public.run_memory_binding AS binding
                    WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id
               ));
        UPDATE public.review_queue AS review_row
           SET subject_digests = review_row.subject_digests
         WHERE review_row.project_id = expected_project_id
           AND review_row.memory_id IN (
               SELECT binding.memory_id FROM public.run_memory_binding AS binding
                WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id
           );
        UPDATE public.memory_status_log AS status_row
           SET subject_digests = status_row.subject_digests
         WHERE status_row.project_id = expected_project_id
           AND status_row.memory_id IN (
               SELECT binding.memory_id FROM public.run_memory_binding AS binding
                WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id
           );
        UPDATE public.memory_q_update AS update_row
           SET subject_digests = update_row.subject_digests
         WHERE update_row.project_id = expected_project_id
           AND update_row.memory_id IN (
               SELECT binding.memory_id FROM public.run_memory_binding AS binding
                WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id
           );
    END IF;

    IF blocking_request IS NOT NULL THEN
        -- The generic write guard intentionally blocks ordinary activity
        -- while an E2 request is nonterminal.  Mint a transaction-bound,
        -- owner-only capability for this one digest-only association so a
        -- late tag cannot disappear through rollback.  Runtime roles have no
        -- direct INSERT privilege on trace_subject, and the guard accepts the
        -- capability only for this `(project, run, txid)` row.
        IF NOT too_many THEN
            INSERT INTO public.erasure_late_bind_capability (
                backend_pid, transaction_id, project_id, run_id, request_id
            ) VALUES (
                pg_catalog.pg_backend_pid(), pg_catalog.txid_current(),
                expected_project_id, expected_run_id, blocking_request
            ) ON CONFLICT (backend_pid, transaction_id) DO UPDATE
              SET project_id = EXCLUDED.project_id,
                  run_id = EXCLUDED.run_id,
                  request_id = EXCLUDED.request_id,
                  issued_at = statement_timestamp();
            INSERT INTO public.trace_subject (project_id, run_id, subject_tag, subject_digest)
            SELECT expected_project_id, expected_run_id, NULL, digest
              FROM unnest(full_digests) AS item(digest)
            ON CONFLICT (project_id, run_id, subject_digest) DO NOTHING;
            DELETE FROM public.trace_subject AS binding
             WHERE binding.project_id = expected_project_id
               AND binding.run_id = expected_run_id
               AND binding.subject_digest = public.tracebed_subject_digest(
                   expected_project_id, '__project__'
               )
               AND EXISTS (
                   SELECT 1 FROM unnest(full_digests) AS item(digest)
                    WHERE digest <> public.tracebed_subject_digest(expected_project_id, '__project__')
               );
            DELETE FROM public.erasure_late_bind_capability
             WHERE backend_pid = pg_catalog.pg_backend_pid()
               AND transaction_id = pg_catalog.txid_current();
        END IF;
        IF run_state = 'live' THEN
            UPDATE public.run_fence
               SET state = 'fenced', request_id = blocking_request,
                   fenced_at = statement_timestamp()
             WHERE project_id = expected_project_id AND run_id = expected_run_id;
        END IF;
        WITH inserted AS (
            INSERT INTO public.erase_run_set (project_id, request_id, run_id)
            VALUES (expected_project_id, blocking_request, expected_run_id)
            ON CONFLICT (project_id, request_id, run_id) DO NOTHING
            RETURNING run_id
        )
        SELECT COALESCE(array_agg(run_id ORDER BY run_id), '{}'::uuid[])
          INTO late_new_run_ids
          FROM inserted;
        -- A late run can already own/point at memory.  Capture that complete
        -- normalized run closure now, rather than relying on a later saga or
        -- an O(project-memory) recovery scan.  As in request acceptance, a
        -- graph that would exceed the bounded proof is refused atomically.
        IF EXISTS (
            WITH RECURSIVE closure(memory_id, closure_depth, path) AS (
                SELECT binding.memory_id, 0, ARRAY[binding.memory_id]
                  FROM public.run_memory_binding AS binding
                 WHERE binding.project_id = expected_project_id
                   AND binding.run_id = expected_run_id
                UNION ALL
                SELECT CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END,
                       closure.closure_depth + 1,
                       closure.path || CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
                  FROM closure
                  JOIN public.memory_link AS link
                    ON link.project_id = expected_project_id
                   AND (link.src_id = closure.memory_id OR link.dst_id = closure.memory_id)
                 WHERE closure.closure_depth < 1024
                   AND NOT (CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
                            = ANY(closure.path))
            )
            SELECT 1
              FROM closure
              JOIN public.memory_link AS next_link
                ON next_link.project_id = expected_project_id
               AND (next_link.src_id = closure.memory_id OR next_link.dst_id = closure.memory_id)
             WHERE closure.closure_depth = 1024
               AND NOT (CASE WHEN next_link.src_id = closure.memory_id
                             THEN next_link.dst_id ELSE next_link.src_id END = ANY(closure.path))
             LIMIT 1
        ) THEN
            RAISE EXCEPTION 'erasure closure exceeds bounded depth' USING ERRCODE = 'P0005';
        END IF;
        WITH RECURSIVE closure(memory_id, closure_depth, path) AS (
            SELECT binding.memory_id, 0, ARRAY[binding.memory_id]
              FROM public.run_memory_binding AS binding
             WHERE binding.project_id = expected_project_id
               AND binding.run_id = expected_run_id
            UNION ALL
            SELECT CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END,
                   closure.closure_depth + 1,
                   closure.path || CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
              FROM closure
              JOIN public.memory_link AS link
                ON link.project_id = expected_project_id
               AND (link.src_id = closure.memory_id OR link.dst_id = closure.memory_id)
             WHERE closure.closure_depth < 1024
               AND NOT (CASE WHEN link.src_id = closure.memory_id THEN link.dst_id ELSE link.src_id END
                        = ANY(closure.path))
        ), inserted AS (
            INSERT INTO public.erase_mem_set (project_id, request_id, memory_id, closure_depth)
            SELECT expected_project_id, blocking_request, closure.memory_id,
                   min(closure.closure_depth)
              FROM closure
             GROUP BY closure.memory_id
            ON CONFLICT ON CONSTRAINT erase_mem_set_pkey DO NOTHING
            RETURNING memory_id
        )
        SELECT COALESCE(array_agg(memory_id ORDER BY memory_id), '{}'::uuid[])
          INTO late_new_mem_ids
          FROM inserted;
        IF cardinality(late_new_run_ids) <> 0 OR cardinality(late_new_mem_ids) <> 0 THEN
            -- One late association has one closure revision.  The private E3
            -- helper stamps only the rows inserted above and atomically makes
            -- all prior DB/external proofs stale.
            PERFORM public.tracebed_erasure_refresh_late_closure(
                expected_project_id, blocking_request, late_new_run_ids, late_new_mem_ids
            );
        END IF;
        RETURN QUERY SELECT COALESCE(full_digests, '{}'::bytea[]), false, NULL::uuid;
        RETURN;
    END IF;
    RETURN QUERY SELECT full_digests, true, NULL::uuid;
END;
$$;

-- Worker-only append of a normalized run→memory relationship.  A learned or
-- reused memory cannot remain discoverable through a run after that run has
-- become fenced: the function repeats the canonical snapshot before it takes
-- the business binding and memory locks, then recomputes the monotone union
-- across every bound run.  Runtime roles retain no direct DML on this table.
CREATE FUNCTION public.tracebed_bind_run_memory(
    expected_project_id uuid,
    expected_run_id uuid,
    expected_memory_id uuid,
    expected_subject_digests bytea[]
) RETURNS bytea[]
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    actual_digests bytea[];
    current_memory_digests bytea[];
    merged_digests bytea[];
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR expected_project_id IS NULL OR expected_run_id IS NULL OR expected_memory_id IS NULL
       OR NOT public.subject_digests_are_valid(expected_subject_digests)
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1 THEN
        RAISE EXCEPTION 'run memory binding denied' USING ERRCODE = '42501';
    END IF;

    -- (2..7) authority/admission, project, sorted run, stable union, sorted
    -- subject fences, and run fence are owned by this one profiled snapshot.
    SELECT public.tracebed_lock_run_subject_snapshot(
        expected_project_id, expected_run_id, expected_subject_digests
    ) INTO actual_digests;

    -- (8) append only after the run snapshot is current.  The next lock is
    -- the memory row (10); no subject key or unrelated business row is taken
    -- in between, preserving the global E2 lock order.
    INSERT INTO public.run_memory_binding (project_id, run_id, memory_id)
    VALUES (expected_project_id, expected_run_id, expected_memory_id)
    ON CONFLICT (project_id, run_id, memory_id) DO NOTHING;

    SELECT memory_row.subject_digests
      INTO current_memory_digests
      FROM public.memory_item AS memory_row
     WHERE memory_row.project_id = expected_project_id
       AND memory_row.id = expected_memory_id
     FOR UPDATE;
    IF NOT FOUND OR NOT public.subject_digests_are_valid(current_memory_digests) THEN
        RAISE EXCEPTION 'run memory binding denied' USING ERRCODE = 'P0003';
    END IF;

    -- A project sentinel represents "unbound/unknown", not a real subject.
    -- Once any bound run supplies a concrete digest it must be refined away;
    -- retaining it beside a subject would make a subject-fence query treat a
    -- selective memory as permanently project-wide.  If there is still no
    -- concrete evidence, retain the prior explicit empty/sentinel value so
    -- an empty declaration is not silently promoted to unknown.
    WITH concrete AS (
        SELECT digest
          FROM unnest(current_memory_digests) AS item(digest)
         WHERE digest <> public.tracebed_subject_digest(expected_project_id, '__project__')
        UNION
        SELECT trace_binding.subject_digest AS digest
          FROM public.run_memory_binding AS binding
          JOIN public.trace_subject AS trace_binding
            ON trace_binding.project_id = binding.project_id
           AND trace_binding.run_id = binding.run_id
         WHERE binding.project_id = expected_project_id
           AND binding.memory_id = expected_memory_id
           AND trace_binding.subject_digest
               <> public.tracebed_subject_digest(expected_project_id, '__project__')
    )
    SELECT COALESCE(
               array_agg(DISTINCT digest ORDER BY digest),
               current_memory_digests
           )
      INTO merged_digests
      FROM concrete;
    IF pg_catalog.cardinality(merged_digests) > 64 THEN
        RAISE EXCEPTION 'run memory attribution capacity denied' USING ERRCODE = 'P0004';
    END IF;
    UPDATE public.memory_item
       SET subject_digests = merged_digests
     WHERE project_id = expected_project_id AND id = expected_memory_id;
    UPDATE public.memory_link AS link_row
       SET subject_digests = link_row.subject_digests
     WHERE link_row.project_id = expected_project_id
       AND (link_row.src_id = expected_memory_id OR link_row.dst_id = expected_memory_id);
    UPDATE public.review_queue AS review_row
       SET subject_digests = review_row.subject_digests
     WHERE review_row.project_id = expected_project_id AND review_row.memory_id = expected_memory_id;
    UPDATE public.memory_status_log AS status_row
       SET subject_digests = status_row.subject_digests
     WHERE status_row.project_id = expected_project_id AND status_row.memory_id = expected_memory_id;
    UPDATE public.memory_q_update AS update_row
       SET subject_digests = update_row.subject_digests
     WHERE update_row.project_id = expected_project_id AND update_row.memory_id = expected_memory_id;
    RETURN merged_digests;
END;
$$;

-- Worker-only no-I/O snapshot guard.  A stale queue payload must be retried
-- from its propagated durable row; a fenced/project-sealed lineage is a
-- refusal, not a chance to perform an external side effect first.
CREATE FUNCTION public.tracebed_lock_run_subject_snapshot(
    expected_project_id uuid,
    expected_run_id uuid,
    expected_subject_digests bytea[]
) RETURNS bytea[]
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    actual_digests bytea[];
    run_state text;
    blocking_request uuid;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR expected_project_id IS NULL OR expected_run_id IS NULL
       OR NOT public.subject_digests_are_valid(expected_subject_digests)
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1 THEN
        RAISE EXCEPTION 'run snapshot denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM public.authority_admission_state
     WHERE singleton AND admissions_open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'run snapshot denied' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || expected_project_id::text, 0)
    );
    SELECT request_row.request_id INTO blocking_request
      FROM public.erasure_request AS request_row
     WHERE request_row.project_id = expected_project_id
       AND (request_row.scope = 'project' OR request_row.disposition <> 'scope_complete')
     ORDER BY request_row.requested_at, request_row.request_id
     LIMIT 1
     FOR SHARE;
    IF FOUND THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended(
            'tracebed.erasure.run/v1:' || expected_project_id::text || ':' || expected_run_id::text,
            0
        )
    );
    SELECT COALESCE(
               array_agg(binding.subject_digest ORDER BY binding.subject_digest),
               ARRAY[public.tracebed_subject_digest(expected_project_id, '__project__')]::bytea[]
           )
      INTO actual_digests
      FROM public.trace_subject AS binding
     WHERE binding.project_id = expected_project_id AND binding.run_id = expected_run_id;
    -- (6) fence rows are locked in sorted digest order before the run fence.
    PERFORM 1 FROM public.subject_fence AS fence
     WHERE fence.project_id = expected_project_id AND fence.subject_digest = ANY(actual_digests)
     ORDER BY fence.subject_digest FOR SHARE;
    IF EXISTS (
        SELECT 1 FROM public.subject_fence AS fence
         WHERE fence.project_id = expected_project_id
           AND fence.subject_digest = ANY(actual_digests)
           AND fence.state <> 'live'
    ) THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
    SELECT fence.state INTO run_state
      FROM public.run_fence AS fence
     WHERE fence.project_id = expected_project_id AND fence.run_id = expected_run_id
     FOR SHARE;
    IF NOT FOUND OR run_state IS DISTINCT FROM 'live' THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
    IF actual_digests IS DISTINCT FROM expected_subject_digests THEN
        RAISE EXCEPTION 'run subject snapshot is stale' USING ERRCODE = 'P0003';
    END IF;
    -- Bind dependent v2 key material to this exact snapshot transaction.
    -- The capability carries the canonical union produced above; it is not a
    -- runtime-set GUC and cannot be fabricated by an API/worker caller.
    DELETE FROM public.erasure_snapshot_capability
     WHERE backend_pid = pg_catalog.pg_backend_pid();
    INSERT INTO public.erasure_snapshot_capability (
        backend_pid, transaction_id, project_id, run_id, subject_digests
    ) VALUES (
        pg_catalog.pg_backend_pid(), pg_catalog.txid_current(),
        expected_project_id, expected_run_id, actual_digests
    );
    RETURN actual_digests;
END;
$$;

-- Trace ingress may create a v2 envelope key only after the profiled worker
-- snapshot above has proven that the digest belongs to this live run in this
-- exact transaction.  Direct worker DML on subject_key is revoked at c12.
CREATE FUNCTION public.tracebed_insert_subject_key_v2(
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

-- Small API/worker durable assertion for project-only and explicit run-bound
-- writes.  It locks/re-derives run attribution itself; caller arrays are a
-- snapshot to verify, never an authority claim that can hide a fenced digest.
CREATE FUNCTION public.tracebed_assert_erasure_write_allowed(
    expected_project_id uuid,
    expected_run_ids uuid[],
    expected_subject_digests bytea[]
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    run_value uuid;
    actual_digests bytea[];
    run_state text;
BEGIN
    IF session_user NOT IN ('tracebed_api', 'tracebed_worker')
       OR NOT pg_catalog.pg_has_role(
           session_user,
           CASE WHEN session_user = 'tracebed_api' THEN 'tracebed_api_group' ELSE 'tracebed_worker_group' END,
           'member'
       )
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL
       OR expected_run_ids IS NULL
       OR (pg_catalog.cardinality(expected_run_ids) <> 0
           AND pg_catalog.array_ndims(expected_run_ids) IS DISTINCT FROM 1)
       OR pg_catalog.array_position(expected_run_ids, NULL::uuid) IS NOT NULL
       OR (SELECT count(*) FROM unnest(expected_run_ids))
          IS DISTINCT FROM (SELECT count(DISTINCT run_id) FROM unnest(expected_run_ids) AS item(run_id))
       OR NOT public.subject_digests_are_valid(expected_subject_digests)
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'erasure write assertion denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM public.authority_admission_state
     WHERE singleton AND admissions_open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'erasure write assertion denied' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || expected_project_id::text, 0)
    );
    IF EXISTS (
        SELECT 1 FROM public.erasure_request AS request_row
         WHERE request_row.project_id = expected_project_id
           AND (request_row.scope = 'project' OR request_row.disposition <> 'scope_complete')
    ) THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
    -- Project-attributed rows use the one internal sentinel and are only
    -- accepted when no concrete run needs to be verified.
    IF pg_catalog.cardinality(expected_run_ids) = 0
       AND expected_subject_digests IS DISTINCT FROM ARRAY[
            public.tracebed_subject_digest(expected_project_id, '__project__')
       ]::bytea[] THEN
        RAISE EXCEPTION 'erasure write assertion denied' USING ERRCODE = '42501';
    END IF;
    -- (4) acquire every run serialization lock before reading one stable
    -- union. No path may inspect/fence subjects between individual run locks.
    FOR run_value IN SELECT run_id FROM unnest(expected_run_ids) AS item(run_id) ORDER BY run_id LOOP
        PERFORM pg_catalog.pg_advisory_xact_lock_shared(
            pg_catalog.hashtextextended(
                'tracebed.erasure.run/v1:' || expected_project_id::text || ':' || run_value::text,
                0
            )
        );
    END LOOP;
    -- (5) derive the canonical union across every selected run. The caller's
    -- array is only a snapshot to compare after this derivation, never a
    -- caller-controlled filter that could omit a fenced identity.
    SELECT COALESCE(
               array_agg(DISTINCT binding.subject_digest ORDER BY binding.subject_digest),
               ARRAY[public.tracebed_subject_digest(expected_project_id, '__project__')]::bytea[]
           )
      INTO actual_digests
      FROM public.trace_subject AS binding
     WHERE binding.project_id = expected_project_id
       AND binding.run_id = ANY(expected_run_ids);
    -- (6) lock every subject fence in the canonical global order.
    PERFORM 1 FROM public.subject_fence AS fence
     WHERE fence.project_id = expected_project_id
       AND fence.subject_digest = ANY(actual_digests)
     ORDER BY fence.subject_digest
     FOR SHARE;
    IF EXISTS (
        SELECT 1 FROM public.subject_fence AS fence
         WHERE fence.project_id = expected_project_id
           AND fence.subject_digest = ANY(actual_digests)
           AND fence.state <> 'live'
    ) THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
    -- (7) only now lock the run fences, after the stable union/fence proof.
    FOR run_value IN SELECT run_id FROM unnest(expected_run_ids) AS item(run_id) ORDER BY run_id LOOP
        SELECT fence.state INTO run_state
          FROM public.run_fence AS fence
         WHERE fence.project_id = expected_project_id AND fence.run_id = run_value
         FOR SHARE;
        IF NOT FOUND OR run_state IS DISTINCT FROM 'live' THEN
            RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
        END IF;
    END LOOP;
    IF pg_catalog.cardinality(expected_run_ids) > 0
       AND actual_digests IS DISTINCT FROM expected_subject_digests THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
END;
$$;

-- Runtime roles deliberately have no ACL on the erasure ledger/fence/set
-- relations.  Read surfaces call these narrowly profiled boolean filters
-- instead of embedding joins to ACL-empty relations in API/worker SQL.  Each
-- helper binds the caller to its transaction-local project GUC before reading
-- anything, so a boolean cannot become a cross-project request oracle.
CREATE FUNCTION public.tracebed_runtime_project_readable(expected_project_id uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF expected_project_id IS NULL
       OR session_user NOT IN ('tracebed_api', 'tracebed_worker')
       OR current_user <> 'tracebed_owner'
       OR NOT pg_catalog.pg_has_role(
            session_user,
            CASE WHEN session_user = 'tracebed_api' THEN 'tracebed_api_group'
                 ELSE 'tracebed_worker_group' END,
            'member'
       )
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RETURN false;
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended(
            'tracebed.erasure.project/v1:' || expected_project_id::text, 0
        )
    );
    RETURN NOT EXISTS (
        SELECT 1
          FROM public.erasure_request AS request_row
         WHERE request_row.project_id = expected_project_id
           AND (request_row.scope = 'project'
                OR request_row.disposition <> 'scope_complete')
    );
END;
$$;

CREATE FUNCTION public.tracebed_runtime_subjects_visible(
    expected_project_id uuid,
    expected_subject_digests bytea[]
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT public.tracebed_runtime_project_readable(expected_project_id)
       OR NOT public.subject_digests_are_valid(expected_subject_digests) THEN
        RETURN false;
    END IF;
    RETURN NOT EXISTS (
        SELECT 1
          FROM public.subject_fence AS fence
         WHERE fence.project_id = expected_project_id
           AND fence.subject_digest = ANY(expected_subject_digests)
           AND fence.state <> 'live'
    );
END;
$$;

CREATE FUNCTION public.tracebed_runtime_run_visible(
    expected_project_id uuid,
    expected_run_id uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    actual_digests bytea[];
BEGIN
    IF expected_run_id IS NULL
       OR NOT public.tracebed_runtime_project_readable(expected_project_id) THEN
        RETURN false;
    END IF;
    SELECT COALESCE(
               array_agg(binding.subject_digest ORDER BY binding.subject_digest),
               ARRAY[public.tracebed_subject_digest(expected_project_id, '__project__')]::bytea[]
           )
      INTO actual_digests
      FROM public.trace_subject AS binding
     WHERE binding.project_id = expected_project_id
       AND binding.run_id = expected_run_id;
    RETURN EXISTS (
        SELECT 1 FROM public.run_fence AS fence
         WHERE fence.project_id = expected_project_id
           AND fence.run_id = expected_run_id
           AND fence.state = 'live'
    ) AND public.tracebed_runtime_subjects_visible(expected_project_id, actual_digests);
END;
$$;

CREATE FUNCTION public.tracebed_runtime_memory_visible(
    expected_project_id uuid,
    expected_memory_id uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    actual_digests bytea[];
BEGIN
    IF expected_memory_id IS NULL
       OR NOT public.tracebed_runtime_project_readable(expected_project_id) THEN
        RETURN false;
    END IF;
    SELECT memory_row.subject_digests
      INTO actual_digests
      FROM public.memory_item AS memory_row
     WHERE memory_row.project_id = expected_project_id
       AND memory_row.id = expected_memory_id;
    IF NOT FOUND
       OR NOT public.tracebed_runtime_subjects_visible(expected_project_id, actual_digests)
       OR EXISTS (
            SELECT 1 FROM public.erase_mem_set AS erased
             WHERE erased.project_id = expected_project_id
               AND erased.memory_id = expected_memory_id
       )
       OR EXISTS (
            SELECT 1
              FROM public.run_memory_binding AS binding
              JOIN public.run_fence AS fence
                ON fence.project_id = binding.project_id
               AND fence.run_id = binding.run_id
             WHERE binding.project_id = expected_project_id
               AND binding.memory_id = expected_memory_id
               AND fence.state <> 'live'
       ) THEN
        RETURN false;
    END IF;
    RETURN true;
END;
$$;

-- API-only queue admission.  The API sends its already-validated business
-- payload, never a digest or run-owner envelope; this function derives the
-- only permitted direct tags from typed topic locations, binds the durable
-- union, then stamps that complete union and server-read owner facts on the
-- queue row in one transaction.
CREATE FUNCTION public.tracebed_enqueue_authorized(
    expected_project_id uuid,
    expected_principal_id uuid,
    expected_agent_type_id uuid,
    expected_grant_id uuid,
    expected_feedback_source text,
    requested_topic text,
    expected_run_id uuid,
    requested_payload jsonb,
    requested_priority integer,
    requested_max_attempts integer,
    requested_available_at timestamptz,
    max_global_depth integer,
    max_topic_depth integer,
    max_project_depth integer,
    requested_enqueue boolean
) RETURNS TABLE (queue_id bigint, writable boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    required_role text;
    direct_tags text[] := '{}'::text[];
    full_digests bytea[];
    bound_writable boolean;
    opened_writable boolean;
    late_bind_eligible boolean;
    owner_principal_id uuid;
    owner_agent_type_id uuid;
    inserted_queue_id bigint;
    global_depth bigint;
    topic_depth bigint;
    project_depth bigint;
    tag_value text;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL OR expected_grant_id IS NULL OR expected_run_id IS NULL
       OR requested_topic NOT IN ('trace_event', 'outcome_event', 'memory_proposal')
       OR requested_payload IS NULL OR jsonb_typeof(requested_payload) <> 'object'
       OR requested_priority NOT BETWEEN 0 AND 1000000
       OR requested_max_attempts NOT BETWEEN 1 AND 100
       OR requested_available_at IS NULL OR NOT isfinite(requested_available_at)
       OR max_global_depth NOT BETWEEN 1 AND 10000000
       OR max_topic_depth NOT BETWEEN 1 AND 10000000
       OR max_project_depth NOT BETWEEN 1 AND 10000000
       OR requested_enqueue IS NULL
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
    END IF;

    required_role := CASE WHEN requested_topic = 'outcome_event' THEN 'feedback' ELSE 'data' END;
    IF (required_role = 'feedback' AND expected_feedback_source NOT IN ('verdict', 'correction_adapter', 'downstream'))
       OR (required_role = 'data' AND expected_feedback_source IS NOT NULL) THEN
        RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM public.tracebed_require_active_grant(
        expected_project_id, expected_principal_id, expected_agent_type_id,
        expected_grant_id, required_role, expected_feedback_source
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
    END IF;

    -- Server-side topic extraction: no arbitrary JSON key can become a
    -- subject identity.  The application may validate shape earlier, but a
    -- direct function caller receives this exact validation again.
    IF requested_topic = 'trace_event' THEN
        IF jsonb_typeof(requested_payload -> 'event') <> 'object'
           OR jsonb_typeof(requested_payload -> 'event' -> 'payload') <> 'object'
           OR jsonb_typeof(requested_payload -> 'seq') <> 'number' THEN
            RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
        END IF;
        IF requested_payload -> 'event' ->> 'type' IN ('artifact_ref', 'state_note')
           AND requested_payload -> 'event' -> 'payload' ? 'subject_tags' THEN
            IF jsonb_typeof(requested_payload -> 'event' -> 'payload' -> 'subject_tags') <> 'array'
               OR EXISTS (
                    SELECT 1
                      FROM jsonb_array_elements(requested_payload -> 'event' -> 'payload' -> 'subject_tags') AS item(value)
                     WHERE jsonb_typeof(item.value) <> 'string'
               ) THEN
                RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
            END IF;
            SELECT COALESCE(array_agg(item.value #>> '{}' ORDER BY item.value #>> '{}' COLLATE "C"), '{}'::text[])
              INTO direct_tags
              FROM jsonb_array_elements(requested_payload -> 'event' -> 'payload' -> 'subject_tags') AS item(value);
        END IF;
    ELSIF requested_topic = 'memory_proposal' THEN
        IF jsonb_typeof(requested_payload -> 'proposal') <> 'object' THEN
            RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
        END IF;
        -- The typed DTO serializes an optional omitted subject tag as JSON
        -- null.  That is the legitimate zero-tag form, not a caller-supplied
        -- identity; only a non-null value may become a direct subject tag.
        IF requested_payload -> 'proposal' ? 'subject_tag'
           AND jsonb_typeof(requested_payload -> 'proposal' -> 'subject_tag') <> 'null' THEN
            IF jsonb_typeof(requested_payload -> 'proposal' -> 'subject_tag') <> 'string' THEN
                RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
            END IF;
            direct_tags := ARRAY[requested_payload -> 'proposal' ->> 'subject_tag'];
        END IF;
    END IF;
    IF pg_catalog.cardinality(direct_tags) > 64
       OR (SELECT count(*) FROM unnest(direct_tags))
              IS DISTINCT FROM (SELECT count(DISTINCT tag COLLATE "C") FROM unnest(direct_tags) AS tag)
       OR EXISTS (SELECT 1 FROM unnest(direct_tags) AS tag
                   WHERE NOT public.tracebed_subject_tag_is_valid(tag, false)) THEN
        RAISE EXCEPTION 'authorized enqueue denied' USING ERRCODE = '42501';
    END IF;

    IF requested_topic = 'trace_event' THEN
        SELECT opened.writable, opened.late_bind_eligible
          INTO opened_writable, late_bind_eligible
          FROM public.tracebed_open_erasure_guarded_run(
              expected_project_id, expected_principal_id, expected_agent_type_id,
              expected_grant_id, expected_run_id, 'trace'
          ) AS opened;
        -- A non-writable existing same-owner live run is allowed to reach the
        -- binder exactly once for late containment.  It can never enqueue
        -- business work: the false result below is committed by the caller
        -- before that caller presents its opaque refusal.
        IF opened_writable IS DISTINCT FROM true
           AND late_bind_eligible IS DISTINCT FROM true THEN
            RETURN QUERY SELECT NULL::bigint, false;
            RETURN;
        END IF;
    ELSE
        SELECT owner_row.principal_id, owner_row.agent_type_id
          INTO owner_principal_id, owner_agent_type_id
          FROM public.run_owner AS owner_row
         WHERE owner_row.project_id = expected_project_id
           AND owner_row.run_id = expected_run_id
         FOR SHARE;
        IF NOT FOUND
           OR (requested_topic = 'memory_proposal' AND (
               owner_principal_id IS DISTINCT FROM expected_principal_id
               OR owner_agent_type_id IS DISTINCT FROM expected_agent_type_id
           )) THEN
            RAISE EXCEPTION 'run authority denied' USING ERRCODE = 'P0002';
        END IF;
    END IF;

    SELECT bound.subject_digests, bound.writable
      INTO full_digests, bound_writable
      FROM public.tracebed_bind_run_subject_tags(
          expected_project_id, expected_principal_id, expected_agent_type_id,
          expected_grant_id, expected_run_id, required_role, direct_tags
      ) AS bound;
    IF bound_writable IS DISTINCT FROM true THEN
        -- The low-level binder has already attached the target, fenced the
        -- run and appended its closure while holding the canonical locks.
        -- Never raise here: raising would roll that containment back with the
        -- outer API transaction.  The Python wrapper commits this row and
        -- then raises ErasureFenced outside its scoped transaction.
        RETURN QUERY SELECT NULL::bigint, false;
        RETURN;
    END IF;
    IF NOT public.subject_digests_are_valid(full_digests) THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0004';
    END IF;
    SELECT owner_row.principal_id, owner_row.agent_type_id
      INTO owner_principal_id, owner_agent_type_id
      FROM public.run_owner AS owner_row
     WHERE owner_row.project_id = expected_project_id
       AND owner_row.run_id = expected_run_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'run authority denied' USING ERRCODE = 'P0002';
    END IF;

    -- Preflight uses the identical authority/tag/open/bind path but performs
    -- no business write.  It lets a batch discover and commit every late
    -- containment result before its caller rejects the whole batch.  A
    -- writable batch makes a second, idempotent call with requested_enqueue
    -- true in the same transaction, preserving bind+enqueue atomicity.
    IF NOT requested_enqueue THEN
        RETURN QUERY SELECT NULL::bigint, true;
        RETURN;
    END IF;

    -- The business queue step is strictly after authority, project/run
    -- serialization, stable-union derivation and fence proof.  These locks
    -- only serialize bounded capacity accounting; they never authorize a run
    -- or examine caller-supplied attribution.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('tracebed.queue.capacity/global/v1', 0)
    );
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('tracebed.queue.capacity/topic/v1:' || requested_topic, 0)
    );
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('tracebed.queue.capacity/project/v1:' || expected_project_id::text, 0)
    );
    SELECT count(*),
           count(*) FILTER (WHERE queue_row.topic = requested_topic),
           count(*) FILTER (WHERE queue_row.project_id = expected_project_id)
      INTO global_depth, topic_depth, project_depth
      FROM public.work_queue AS queue_row;
    IF global_depth >= max_global_depth
       OR topic_depth >= max_topic_depth
       OR project_depth >= max_project_depth THEN
        RAISE EXCEPTION 'authorized queue full' USING ERRCODE = 'P0006';
    END IF;

    INSERT INTO public.work_queue (
        project_id, topic, payload, priority, attempts, max_attempts,
        available_at, created_at, authority_version, run_id,
        source_principal_id, source_agent_type_id, source_grant_id,
        required_role, feedback_source, run_owner_principal_id,
        run_owner_agent_type_id, subject_digests
    ) VALUES (
        expected_project_id, requested_topic, requested_payload, requested_priority,
        0, requested_max_attempts, requested_available_at, statement_timestamp(),
        1, expected_run_id, expected_principal_id, expected_agent_type_id,
        expected_grant_id, required_role,
        CASE WHEN required_role = 'feedback' THEN expected_feedback_source ELSE NULL END,
        owner_principal_id, owner_agent_type_id, full_digests
    ) RETURNING id INTO inserted_queue_id;
    RETURN QUERY SELECT inserted_queue_id, true;
    RETURN;
END;
$$;

-- API-only invalidation admission.  Selectors have no authoritative run
-- binding in E2, so this writes the internal project attribution rather than
-- accepting a caller-provided digest.  Direct API INSERT is revoked below;
-- this profiled routine owns the exact grant, admission, project-lock and
-- durable-quiescence proof in one transaction.
CREATE FUNCTION public.tracebed_insert_authorized_invalidation(
    expected_project_id uuid,
    expected_principal_id uuid,
    expected_agent_type_id uuid,
    expected_grant_id uuid,
    requested_event_type text,
    requested_selector jsonb
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    inserted_event_id uuid;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_project_id IS NULL OR expected_principal_id IS NULL
       OR expected_agent_type_id IS NULL OR expected_grant_id IS NULL
       OR requested_event_type IS NULL OR octet_length(requested_event_type) NOT BETWEEN 1 AND 128
       OR (requested_selector IS NOT NULL AND jsonb_typeof(requested_selector) <> 'object')
       OR (requested_selector IS NOT NULL AND octet_length(requested_selector::text) > 16384)
       OR pg_catalog.current_setting('tracebed.project_id', true)
              IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'authorized invalidation denied' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM public.tracebed_require_active_grant(
        expected_project_id, expected_principal_id, expected_agent_type_id,
        expected_grant_id, 'data', NULL
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authorized invalidation denied' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || expected_project_id::text, 0)
    );
    IF public.tracebed_erasure_project_is_quiesced(expected_project_id) THEN
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
    INSERT INTO public.invalidation_event (
        project_id, event_type, selector, subject_digests, fired_at
    ) VALUES (
        expected_project_id, requested_event_type, requested_selector,
        ARRAY[public.tracebed_subject_digest(expected_project_id, '__project__')]::bytea[],
        statement_timestamp()
    ) RETURNING event_id INTO inserted_event_id;
    RETURN inserted_event_id;
END;
$$;

-- Worker-only global claim/disposition surface.  RLS intentionally prevents
-- a raw worker session from scanning all projects; this SECURITY DEFINER
-- routine is the sole global scheduler and returns only rows it has claimed.
CREATE FUNCTION public.tracebed_worker_queue_claim(
    requested_topic text,
    requested_lease interval,
    requested_limit integer
) RETURNS TABLE (
    id bigint, project_id uuid, topic text, payload jsonb, priority integer,
    attempts integer, max_attempts integer, available_at timestamptz,
    created_at timestamptz, lease_expires_at timestamptz,
    authority_version smallint, run_id uuid, source_principal_id uuid,
    source_agent_type_id uuid, source_grant_id uuid, required_role text,
    feedback_source text, run_owner_principal_id uuid,
    run_owner_agent_type_id uuid, subject_digests bytea[]
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    candidate public.work_queue%ROWTYPE;
    claimed_rows integer := 0;
    claimed_count integer := 0;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR requested_topic NOT IN ('trace_event', 'outcome_event', 'memory_proposal')
       OR requested_lease IS NULL OR requested_lease <= interval '0 seconds'
       OR requested_lease > interval '24 hours'
       OR requested_limit NOT BETWEEN 1 AND 100
       OR NULLIF(pg_catalog.current_setting('tracebed.project_id', true), '') IS NOT NULL THEN
        RAISE EXCEPTION 'worker queue claim denied' USING ERRCODE = '42501';
    END IF;
    -- Filter the durable request state *before* LIMIT.  The function runs
    -- owner-only under its profiled SECURITY DEFINER contract, while raw
    -- worker sessions retain no request-table ACL.  A post-LIMIT skip would
    -- repeatedly rescan a fenced priority prefix and starve an unrelated
    -- ready project forever.
    FOR candidate IN
        SELECT queue_row.*
          FROM public.work_queue AS queue_row
         WHERE queue_row.topic = requested_topic
           AND queue_row.available_at <= pg_catalog.now()
           AND (queue_row.lease_expires_at IS NULL OR queue_row.lease_expires_at < pg_catalog.now())
           AND NOT EXISTS (
               SELECT 1
                 FROM public.erasure_request AS request_row
                WHERE request_row.project_id = queue_row.project_id
                  AND (
                      request_row.scope = 'project'
                      OR request_row.disposition <> 'scope_complete'
                  )
           )
         ORDER BY queue_row.priority, queue_row.id
         FOR UPDATE SKIP LOCKED
         LIMIT requested_limit
    LOOP
        PERFORM pg_catalog.set_config('tracebed.project_id', candidate.project_id::text, true);
        -- The durable trigger is the race backstop after the request-state
        -- precheck.  Keep its P0002 inside a subtransaction: one project
        -- becoming fenced must merely skip that candidate, never abort a
        -- global scheduler claim or roll back rows already leased elsewhere.
        BEGIN
            IF EXISTS (
                SELECT 1 FROM public.erasure_request AS request_row
                 WHERE request_row.project_id = candidate.project_id
                   AND (request_row.scope = 'project'
                        OR request_row.disposition <> 'scope_complete')
            ) THEN
                CONTINUE;
            END IF;
            IF candidate.attempts > candidate.max_attempts THEN
                DELETE FROM public.work_queue
                 WHERE work_queue.id = candidate.id
                   AND work_queue.attempts = candidate.attempts
                   AND work_queue.lease_expires_at IS NOT DISTINCT FROM candidate.lease_expires_at;
                IF FOUND THEN
                    INSERT INTO public.dead_letter (
                        id, project_id, topic, payload, priority, attempts, max_attempts,
                        available_at, created_at, lease_expires_at, authority_version, run_id,
                        source_principal_id, source_agent_type_id, source_grant_id, required_role,
                        feedback_source, run_owner_principal_id, run_owner_agent_type_id,
                        subject_digests, failed_at, last_error
                    ) VALUES (
                        candidate.id, candidate.project_id, candidate.topic, candidate.payload,
                        candidate.priority, candidate.attempts, candidate.max_attempts,
                        candidate.available_at, candidate.created_at, candidate.lease_expires_at,
                        candidate.authority_version, candidate.run_id, candidate.source_principal_id,
                        candidate.source_agent_type_id, candidate.source_grant_id, candidate.required_role,
                        candidate.feedback_source, candidate.run_owner_principal_id,
                        candidate.run_owner_agent_type_id, candidate.subject_digests,
                        pg_catalog.now(), 'max_attempts_exceeded'
                    );
                END IF;
                CONTINUE;
            END IF;
            RETURN QUERY
            UPDATE public.work_queue
               SET lease_expires_at = pg_catalog.now() + requested_lease,
                   attempts = work_queue.attempts + 1
             WHERE work_queue.id = candidate.id
               AND work_queue.attempts = candidate.attempts
               AND work_queue.lease_expires_at IS NOT DISTINCT FROM candidate.lease_expires_at
               AND work_queue.authority_version = 1
             RETURNING work_queue.id, work_queue.project_id, work_queue.topic,
                       work_queue.payload, work_queue.priority, work_queue.attempts,
                       work_queue.max_attempts, work_queue.available_at,
                       work_queue.created_at, work_queue.lease_expires_at,
                       work_queue.authority_version, work_queue.run_id,
                       work_queue.source_principal_id, work_queue.source_agent_type_id,
                       work_queue.source_grant_id, work_queue.required_role,
                       work_queue.feedback_source, work_queue.run_owner_principal_id,
                       work_queue.run_owner_agent_type_id, work_queue.subject_digests;
            GET DIAGNOSTICS claimed_rows = ROW_COUNT;
            claimed_count := claimed_count + claimed_rows;
        EXCEPTION WHEN SQLSTATE 'P0002' THEN
            claimed_rows := 0;
        END;
        EXIT WHEN claimed_count >= requested_limit;
    END LOOP;
END;
$$;

CREATE FUNCTION public.tracebed_worker_queue_disposition(
    expected_id bigint,
    expected_attempts integer,
    expected_lease_expires_at timestamptz,
    requested_action text,
    requested_backoff interval,
    requested_reason text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    candidate public.work_queue%ROWTYPE;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR expected_id IS NULL OR expected_id < 1
       OR expected_attempts IS NULL OR expected_attempts < 1
       OR expected_lease_expires_at IS NULL OR NOT isfinite(expected_lease_expires_at)
       OR requested_action NOT IN ('ack', 'nack', 'reject')
       OR (requested_action = 'nack' AND (requested_backoff IS NULL
           OR requested_backoff < interval '0 seconds' OR requested_backoff > interval '24 hours'))
       OR (requested_action <> 'nack' AND requested_backoff IS NOT NULL)
       OR (requested_action = 'reject' AND requested_reason NOT IN (
           'malformed_authority', 'malformed_business_payload',
           'authority_payload_shadow', 'owner_conflict',
           'outcome_replay_conflict', 'proposal_authority_conflict',
           'max_attempts_exceeded'
       ))
       OR (requested_action <> 'reject' AND requested_reason IS NOT NULL) THEN
        RAISE EXCEPTION 'worker queue disposition denied' USING ERRCODE = '42501';
    END IF;
    SELECT queue_row.* INTO candidate
      FROM public.work_queue AS queue_row
     WHERE queue_row.id = expected_id
       AND queue_row.attempts = expected_attempts
       AND queue_row.lease_expires_at IS NOT DISTINCT FROM expected_lease_expires_at
       AND queue_row.authority_version = 1
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM pg_catalog.set_config('tracebed.project_id', candidate.project_id::text, true);
    IF EXISTS (
        SELECT 1 FROM public.erasure_request AS request_row
         WHERE request_row.project_id = candidate.project_id
           AND (request_row.scope = 'project'
                OR request_row.disposition <> 'scope_complete')
    ) THEN
        RETURN false;
    END IF;
    IF requested_action = 'ack' THEN
        DELETE FROM public.work_queue
         WHERE id = candidate.id
           AND attempts = candidate.attempts
           AND lease_expires_at IS NOT DISTINCT FROM candidate.lease_expires_at;
        RETURN FOUND;
    ELSIF requested_action = 'nack' THEN
        UPDATE public.work_queue
           SET available_at = pg_catalog.now() + requested_backoff,
               lease_expires_at = NULL
         WHERE id = candidate.id
           AND attempts = candidate.attempts
           AND lease_expires_at IS NOT DISTINCT FROM candidate.lease_expires_at;
        RETURN FOUND;
    END IF;
    DELETE FROM public.work_queue
     WHERE id = candidate.id
       AND attempts = candidate.attempts
       AND lease_expires_at IS NOT DISTINCT FROM candidate.lease_expires_at;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    INSERT INTO public.dead_letter (
        id, project_id, topic, payload, priority, attempts, max_attempts,
        available_at, created_at, lease_expires_at, authority_version, run_id,
        source_principal_id, source_agent_type_id, source_grant_id, required_role,
        feedback_source, run_owner_principal_id, run_owner_agent_type_id,
        subject_digests, failed_at, last_error
    ) VALUES (
        candidate.id, candidate.project_id, candidate.topic, candidate.payload,
        candidate.priority, candidate.attempts, candidate.max_attempts,
        candidate.available_at, candidate.created_at, candidate.lease_expires_at,
        candidate.authority_version, candidate.run_id, candidate.source_principal_id,
        candidate.source_agent_type_id, candidate.source_grant_id, candidate.required_role,
        candidate.feedback_source, candidate.run_owner_principal_id,
        candidate.run_owner_agent_type_id, candidate.subject_digests,
        pg_catalog.now(), requested_reason
    );
    RETURN true;
EXCEPTION WHEN SQLSTATE 'P0002' THEN
    -- The durable trigger is the race backstop after the precheck above.  A
    -- request that wins this race leaves the leased row untouched for a later
    -- controlled reclaim; it is never transformed into a dead letter.
    RETURN false;
END;
$$;

CREATE FUNCTION public.tracebed_worker_queue_metrics(requested_topic text)
RETURNS TABLE (depth bigint, oldest_available_at timestamptz, dead_count bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (
                SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user
            )) <> 1
       OR requested_topic NOT IN ('trace_event', 'outcome_event', 'memory_proposal')
       OR NULLIF(pg_catalog.current_setting('tracebed.project_id', true), '') IS NOT NULL THEN
        RAISE EXCEPTION 'worker queue metrics denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT (SELECT count(*) FROM public.work_queue WHERE topic = requested_topic),
           (SELECT min(available_at) FROM public.work_queue WHERE topic = requested_topic),
           (SELECT count(*) FROM public.dead_letter WHERE topic = requested_topic);
END;
$$;

-- Runtime publication stays deliberately closed after the foundational
-- catalog migration.  Preserve the B3 physical-login proof, but bind it to
-- the authenticated c12 catalog and to an explicitly activated erasure
-- singleton.  A later lifecycle packet owns that activation; E1 never does.
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

-- v2 wrap bindings are opaque digests.  This overload exists beside the
-- c11 tag helper so historical v1 readers remain wire-compatible while the
-- c12 finalizer never has to recover a v2 tag merely to take its key-row
-- fence.
CREATE FUNCTION public.tracebed_lock_subject_bindings(
    expected_project_id uuid,
    expected_subject_digests bytea[]
) RETURNS TABLE (subject_digest bytea, key_id uuid, destroyed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_worker'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_worker_group', 'member')
       OR expected_project_id IS NULL
       OR NOT public.subject_digests_are_valid(expected_subject_digests)
       OR pg_catalog.cardinality(expected_subject_digests) NOT BETWEEN 1 AND 64
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
    SELECT key_row.subject_digest, key_row.key_id, key_row.destroyed_at
      FROM public.subject_key AS key_row
     WHERE key_row.project_id = expected_project_id
       AND key_row.subject_digest = ANY(expected_subject_digests)
     ORDER BY key_row.subject_digest
     FOR UPDATE;
END;
$$;

-- c12 publishes no raw API producer or global worker scheduler privilege.
-- Partition leaves carry their own ACLs, so revoke the parent and every live
-- leaf explicitly rather than assuming a parent REVOKE reaches old leaves.
REVOKE SELECT, INSERT, UPDATE, DELETE ON public.work_queue FROM tracebed_api_group, tracebed_worker_group;
REVOKE SELECT, INSERT, UPDATE, DELETE ON public.dead_letter FROM tracebed_api_group, tracebed_worker_group;
REVOKE USAGE, SELECT ON SEQUENCE public.work_queue_id_seq FROM tracebed_api_group;
REVOKE INSERT, UPDATE, DELETE ON public.run_owner, public.trace_subject, public.subject_key,
                                 public.invalidation_event
    FROM tracebed_api_group, tracebed_worker_group;
DO $$
DECLARE
    child_name text;
    parent_name text;
BEGIN
    FOREACH parent_name IN ARRAY ARRAY['run_owner', 'trace_subject', 'subject_key', 'invalidation_event'] LOOP
        FOR child_name IN
            SELECT child.relname
              FROM pg_catalog.pg_inherits AS inheritance
              JOIN pg_catalog.pg_class AS parent ON parent.oid = inheritance.inhparent
              JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
              JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = child.relnamespace
             WHERE parent.relnamespace = 'public'::regnamespace
               AND parent.relname = parent_name AND namespace.nspname = 'public'
        LOOP
            EXECUTE format(
                'REVOKE INSERT, UPDATE, DELETE ON public.%I FROM tracebed_api_group, tracebed_worker_group',
                child_name
            );
        END LOOP;
    END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION public.tracebed_mark_erasure_activity() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_mark_erasure_activity_trigger() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.subject_key_enforce_lifecycle() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.erasure_request_enforce_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.erasure_step_receipt_append_only() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_fence_enforce_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_set_append_only() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_run_memory_binding_append_only() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_project_is_quiesced(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_runtime_erasure_read_allowed(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_runtime_erasure_write_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_run_subject_attribution_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_memory_subject_attribution_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_memory_link_subject_attribution_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_memory_item_subject_attribution_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_project_subject_attribution_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.run_owner_enforce_immutability() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.trace_index_enforce_terminal_immutability() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_codes_are_valid(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_subject_tag_is_valid(text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_subject_digest(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_envelope_versions_are_valid(smallint[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_lock_subject_bindings(uuid, bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_request_erasure(uuid, uuid, uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_request_status(uuid, uuid, uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_open_erasure_guarded_run(uuid, uuid, uuid, uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_bind_run_subject_tags(uuid, uuid, uuid, uuid, uuid, text, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_bind_run_memory(uuid, uuid, uuid, bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_lock_run_subject_snapshot(uuid, uuid, bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_insert_subject_key_v2(uuid, bytea, uuid, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_assert_erasure_write_allowed(uuid, uuid[], bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_runtime_project_readable(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_runtime_subjects_visible(uuid, bytea[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_runtime_run_visible(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_runtime_memory_visible(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_enqueue_authorized(uuid, uuid, uuid, uuid, text, text, uuid, jsonb, integer, integer, timestamptz, integer, integer, integer, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_insert_authorized_invalidation(uuid, uuid, uuid, uuid, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_worker_queue_claim(text, interval, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_worker_queue_disposition(bigint, integer, timestamptz, text, interval, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_worker_queue_metrics(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.tracebed_subject_tag_is_valid(text, boolean),
                          public.tracebed_subject_digest(uuid, text),
                          public.tracebed_envelope_versions_are_valid(smallint[])
    TO tracebed_api_group, tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_lock_subject_bindings(uuid, bytea[])
    TO tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_project_is_quiesced(uuid),
                          public.tracebed_runtime_erasure_read_allowed(uuid)
    TO tracebed_api_group, tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_runtime_project_readable(uuid),
                          public.tracebed_runtime_subjects_visible(uuid, bytea[]),
                          public.tracebed_runtime_run_visible(uuid, uuid),
                          public.tracebed_runtime_memory_visible(uuid, uuid)
    TO tracebed_api_group, tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_request_erasure(uuid, uuid, uuid, uuid, text, text),
                          public.tracebed_erasure_request_status(uuid, uuid, uuid, uuid, uuid)
    TO tracebed_api_group;
GRANT EXECUTE ON FUNCTION public.tracebed_open_erasure_guarded_run(uuid, uuid, uuid, uuid, uuid, text),
                          public.tracebed_bind_run_subject_tags(uuid, uuid, uuid, uuid, uuid, text, text[])
    TO tracebed_api_group;
GRANT EXECUTE ON FUNCTION public.tracebed_lock_run_subject_snapshot(uuid, uuid, bytea[])
    TO tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_insert_subject_key_v2(uuid, bytea, uuid, bytea)
    TO tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_bind_run_memory(uuid, uuid, uuid, bytea[])
    TO tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_assert_erasure_write_allowed(uuid, uuid[], bytea[])
    TO tracebed_api_group, tracebed_worker_group;
GRANT EXECUTE ON FUNCTION public.tracebed_enqueue_authorized(uuid, uuid, uuid, uuid, text, text, uuid, jsonb, integer, integer, timestamptz, integer, integer, integer, boolean)
    TO tracebed_api_group;
GRANT EXECUTE ON FUNCTION public.tracebed_insert_authorized_invalidation(uuid, uuid, uuid, uuid, text, jsonb)
    TO tracebed_api_group;
GRANT EXECUTE ON FUNCTION public.tracebed_worker_queue_claim(text, interval, integer),
                          public.tracebed_worker_queue_disposition(bigint, integer, timestamptz, text, interval, text),
                          public.tracebed_worker_queue_metrics(text)
    TO tracebed_worker_group;
REVOKE ALL ON subject_fence, run_fence, erase_run_set, erase_mem_set, run_memory_binding,
              erasure_request, erasure_step_receipt, erasure_cutover_state,
              erasure_late_bind_capability, erasure_snapshot_capability
    FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
         tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;

-- The profile epoch is appended after the E3 tables, functions, and ACLs
-- below.  Keeping it last makes the c12 root authenticate the full artifact.

-- E3 remains part of the unreleased c12 artifact.  The request/fence path
-- above remains wire-compatible; this suffix adds the separately credentialed
-- executor state and is deliberately not granted to either runtime identity.
ALTER TABLE public.erasure_request
    ADD COLUMN first_started_at timestamptz,
    ADD COLUMN retry_count integer NOT NULL DEFAULT 0,
    ADD COLUMN closure_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN closure_digest bytea,
    ADD COLUMN store_manifest text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN store_manifest_digest bytea,
    ADD COLUMN last_receipt_digest bytea,
    ADD COLUMN next_step_seq bigint NOT NULL DEFAULT 1,
    ADD COLUMN verified_at timestamptz;
ALTER TABLE public.erasure_request
    ADD CONSTRAINT erasure_request_global_request_id_uq UNIQUE (request_id),
    ADD CONSTRAINT erasure_request_closure_revision_ck CHECK (closure_revision >= 0),
    ADD CONSTRAINT erasure_request_retry_count_ck CHECK (retry_count >= 0),
    ADD CONSTRAINT erasure_request_closure_digest_ck CHECK (
        (closure_revision = 0 AND closure_digest IS NULL)
        OR (closure_revision >= 1 AND octet_length(closure_digest) = 32)
    ),
    ADD CONSTRAINT erasure_request_manifest_digest_ck CHECK (
        (cardinality(store_manifest) = 0 AND store_manifest_digest IS NULL)
        OR (cardinality(store_manifest) = 4 AND octet_length(store_manifest_digest) = 32)
    ),
    ADD CONSTRAINT erasure_request_receipt_pointer_ck CHECK (
        next_step_seq >= 1
        AND (last_receipt_digest IS NULL OR octet_length(last_receipt_digest) = 32)
    );

ALTER TABLE public.erase_run_set ADD COLUMN discovered_revision bigint NOT NULL DEFAULT 1;
ALTER TABLE public.erase_mem_set ADD COLUMN discovered_revision bigint NOT NULL DEFAULT 1;
ALTER TABLE public.erase_run_set
    ADD CONSTRAINT erase_run_set_discovered_revision_ck CHECK (discovered_revision >= 1);
ALTER TABLE public.erase_mem_set
    ADD CONSTRAINT erase_mem_set_discovered_revision_ck CHECK (discovered_revision >= 1);

ALTER TABLE public.erasure_step_receipt
    ADD COLUMN previous_receipt_digest bytea,
    ADD COLUMN result_code text NOT NULL DEFAULT 'ok',
    ADD COLUMN work_revision bigint NOT NULL DEFAULT 1;
ALTER TABLE public.erasure_step_receipt DROP CONSTRAINT erasure_step_receipt_generation_ck;
ALTER TABLE public.erasure_step_receipt
    ADD CONSTRAINT erasure_step_receipt_generation_ck CHECK (
        (step_code = 'fence' AND generation = 0)
        OR (step_code <> 'fence' AND generation >= 1)
    ),
    ADD CONSTRAINT erasure_step_receipt_previous_ck CHECK (
        previous_receipt_digest IS NULL OR octet_length(previous_receipt_digest) = 32
    ),
    ADD CONSTRAINT erasure_step_receipt_result_code_ck CHECK (
        result_code IN (
            'ok','already_absent','not_configured','embedded_primary','closure_changed',
            'dependency_unavailable','dependency_timeout','verification_failed',
            'configuration_mismatch','store_refused','catalog_mismatch','unsafe_path',
            'integrity_failed','operator_resumed'
        )
    ),
    ADD CONSTRAINT erasure_step_receipt_work_revision_ck CHECK (work_revision >= 1);

CREATE TABLE public.erasure_external_work (
    work_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL,
    request_id uuid NOT NULL,
    store_code text NOT NULL,
    target_kind text NOT NULL,
    target_id uuid,
    discovered_revision bigint NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    attempt integer NOT NULL DEFAULT 0,
    claimed_generation integer,
    claimed_token uuid,
    started_at timestamptz,
    verified_at timestamptz,
    affected_rows bigint,
    last_result_code text,
    postcondition_digest bytea,
    CONSTRAINT erasure_external_work_request_fk FOREIGN KEY (project_id, request_id)
        REFERENCES public.erasure_request(project_id, request_id),
    CONSTRAINT erasure_external_work_store_ck CHECK (store_code IN (
        'trace_fs_v1','trace_s3_v1','valkey_v1','vector_postgres','vector_qdrant',
        'vector_none','graph_postgres','graph_age','graph_none'
    )),
    CONSTRAINT erasure_external_work_target_ck CHECK (
        (target_kind = 'run' AND target_id IS NOT NULL) OR (target_kind = 'project' AND target_id IS NULL)
    ),
    CONSTRAINT erasure_external_work_state_ck CHECK (state IN ('pending','in_progress','verified')),
    CONSTRAINT erasure_external_work_revision_ck CHECK (discovered_revision >= 1),
    CONSTRAINT erasure_external_work_attempt_ck CHECK (attempt >= 0),
    CONSTRAINT erasure_external_work_claim_ck CHECK (
        (state = 'pending' AND claimed_generation IS NULL AND claimed_token IS NULL AND started_at IS NULL)
        OR (state = 'in_progress' AND claimed_generation >= 1 AND claimed_token IS NOT NULL AND started_at IS NOT NULL)
        OR (state = 'verified' AND claimed_generation >= 1 AND claimed_token IS NOT NULL AND started_at IS NOT NULL
            AND verified_at IS NOT NULL AND affected_rows >= 0 AND last_result_code IS NOT NULL
            AND octet_length(postcondition_digest) = 32)
    ),
    CONSTRAINT erasure_external_work_result_code_ck CHECK (last_result_code IS NULL OR last_result_code IN (
        'ok','already_absent','not_configured','embedded_primary','closure_changed',
        'dependency_unavailable','dependency_timeout','verification_failed',
        'configuration_mismatch','store_refused','catalog_mismatch','unsafe_path',
        'integrity_failed','operator_resumed'
    )),
    UNIQUE NULLS NOT DISTINCT (project_id, request_id, store_code, target_kind, target_id)
);

CREATE TABLE public.erasure_store_checkpoint (
    project_id uuid NOT NULL,
    request_id uuid NOT NULL,
    store_code text NOT NULL,
    prepared_revision bigint NOT NULL,
    verified_revision bigint,
    target_count bigint NOT NULL DEFAULT 0,
    target_manifest_digest bytea,
    postcondition_digest bytea,
    result_code text,
    verified_at timestamptz,
    PRIMARY KEY (project_id, request_id, store_code),
    CONSTRAINT erasure_store_checkpoint_request_fk FOREIGN KEY (project_id, request_id)
        REFERENCES public.erasure_request(project_id, request_id),
    CONSTRAINT erasure_store_checkpoint_store_ck CHECK (store_code IN (
        'trace_fs_v1','trace_s3_v1','valkey_v1','vector_postgres','vector_qdrant',
        'vector_none','graph_postgres','graph_age','graph_none'
    )),
    CONSTRAINT erasure_store_checkpoint_shape_ck CHECK (
        prepared_revision >= 1 AND target_count >= 0
        AND (verified_revision IS NULL OR (verified_revision >= prepared_revision
             AND octet_length(target_manifest_digest) = 32 AND octet_length(postcondition_digest) = 32
             AND result_code IS NOT NULL AND verified_at IS NOT NULL))
    )
);

CREATE TABLE public.erasure_execution_capability (
    backend_pid integer NOT NULL,
    transaction_id bigint NOT NULL,
    project_id uuid NOT NULL,
    request_id uuid NOT NULL,
    generation integer NOT NULL,
    lease_token uuid NOT NULL,
    operation text NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation),
    CONSTRAINT erasure_execution_capability_operation_ck CHECK (operation IN (
        'request_update','receipt_insert','key_destroy','primary_purge','external_work',
        'checkpoint','fence_finalize','project_tombstone','closure_refresh'
    )),
    CONSTRAINT erasure_execution_capability_time_ck CHECK (isfinite(issued_at))
);

ALTER TABLE public.erasure_external_work ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_external_work FORCE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_store_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_store_checkpoint FORCE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_execution_capability ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.erasure_execution_capability FORCE ROW LEVEL SECURITY;
CREATE POLICY erasure_external_work_owner_only ON public.erasure_external_work
    USING (current_user = 'tracebed_owner') WITH CHECK (current_user = 'tracebed_owner');
CREATE POLICY erasure_store_checkpoint_owner_only ON public.erasure_store_checkpoint
    USING (current_user = 'tracebed_owner') WITH CHECK (current_user = 'tracebed_owner');
CREATE POLICY erasure_execution_capability_owner_only ON public.erasure_execution_capability
    USING (current_user = 'tracebed_owner') WITH CHECK (current_user = 'tracebed_owner');

CREATE TRIGGER erasure_external_work_activity AFTER INSERT OR UPDATE OR DELETE
    ON public.erasure_external_work FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER erasure_store_checkpoint_activity AFTER INSERT OR UPDATE OR DELETE
    ON public.erasure_store_checkpoint FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();
CREATE TRIGGER erasure_execution_capability_activity AFTER INSERT OR UPDATE OR DELETE
    ON public.erasure_execution_capability FOR EACH ROW EXECUTE FUNCTION public.tracebed_mark_erasure_activity_trigger();

CREATE OR REPLACE FUNCTION public.tracebed_erasure_manifest_is_valid(codes text[])
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT cardinality(codes) = 4
       AND array_ndims(codes) = 1
       AND codes = ARRAY(
            SELECT value.code FROM unnest(codes) AS value(code)
            ORDER BY value.code COLLATE "C"
       )
       AND cardinality(ARRAY(SELECT DISTINCT unnest(codes))) = 4
       AND (SELECT count(*) FROM unnest(codes) AS value(code)
             WHERE code IN ('trace_fs_v1','trace_s3_v1')) = 1
       AND (SELECT count(*) FROM unnest(codes) AS value(code) WHERE code = 'valkey_v1') = 1
       AND (SELECT count(*) FROM unnest(codes) AS value(code)
             WHERE code IN ('vector_postgres','vector_qdrant','vector_none')) = 1
       AND (SELECT count(*) FROM unnest(codes) AS value(code)
             WHERE code IN ('graph_postgres','graph_age','graph_none')) = 1
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_frame(value bytea)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT int8send(octet_length(value)) || value
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_closure_digest(
    expected_project_id uuid, expected_request_id uuid, expected_revision bigint
) RETURNS bytea
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    -- Do not hash every subject fence in the project.  Those rows are lock
    -- witnesses for normal ingress too, so including them would let unrelated
    -- activity mutate a request's proof.  The request identity plus its
    -- append-only run/memory closure is the complete E3 closure instead.
    WITH frames AS (
        SELECT decode('53','hex') || COALESCE(request_row.subject_digest, ''::bytea) AS frame
          FROM public.erasure_request AS request_row
         WHERE request_row.project_id = expected_project_id
           AND request_row.request_id = expected_request_id
        UNION ALL
        SELECT decode('52','hex') || uuid_send(run_id) || int8send(discovered_revision) AS frame
          FROM public.erase_run_set
         WHERE project_id = expected_project_id AND request_id = expected_request_id
        UNION ALL
        SELECT decode('4d','hex') || uuid_send(memory_id) || int8send(closure_depth)
               || int8send(discovered_revision) AS frame
          FROM public.erase_mem_set
         WHERE project_id = expected_project_id AND request_id = expected_request_id
    )
    SELECT sha256(convert_to('tracebed.erasure-closure/v1','UTF8')
        || uuid_send(expected_project_id) || uuid_send(expected_request_id) || int8send(expected_revision)
        || COALESCE((SELECT string_agg(frame, ''::bytea ORDER BY frame) FROM frames), ''::bytea))
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_manifest_digest(codes text[])
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT sha256(convert_to('tracebed.erasure-manifest/v1','UTF8')
        || COALESCE((SELECT string_agg(public.tracebed_erasure_frame(convert_to(code,'UTF8')), ''::bytea)
                     FROM unnest(codes) AS item(code)), ''::bytea))
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_assert_caller()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    login_role record;
BEGIN
    SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
           role.rolreplication, role.rolbypassrls
      INTO login_role
      FROM pg_catalog.pg_roles AS role WHERE role.rolname = session_user;
    IF current_user IS DISTINCT FROM 'tracebed_owner'
       OR session_user IS NULL OR session_user = current_user
       OR NOT FOUND OR NOT login_role.rolcanlogin OR login_role.rolsuper
       OR login_role.rolcreatedb OR login_role.rolcreaterole OR login_role.rolreplication
       OR login_role.rolbypassrls
       OR (SELECT count(*) FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = session_user)) <> 1
       OR NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_auth_members AS membership
             JOIN pg_catalog.pg_roles AS group_role ON group_role.oid = membership.roleid
             JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
             WHERE group_role.rolname = 'tracebed_erasure_group'
               AND member_role.rolname = session_user
               AND membership.admin_option IS FALSE AND membership.inherit_option IS TRUE
               AND membership.set_option IS FALSE
       ) THEN
        RAISE EXCEPTION 'erasure executor denied' USING ERRCODE = '42501';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_assert_lease(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS public.erasure_request
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE;
BEGIN
    PERFORM public.tracebed_erasure_assert_caller();
    IF expected_project_id IS NULL OR expected_request_id IS NULL OR expected_generation < 1
       OR expected_lease_token IS NULL OR expected_owner IS NULL
       OR expected_owner !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$'
       OR pg_catalog.current_setting('tracebed.project_id', true) IS DISTINCT FROM expected_project_id::text THEN
        RAISE EXCEPTION 'erasure invocation denied' USING ERRCODE = 'P0010';
    END IF;
    SELECT * INTO request_row FROM public.erasure_request
     WHERE project_id = expected_project_id AND request_id = expected_request_id FOR UPDATE;
    IF NOT FOUND OR request_row.disposition <> 'active' OR request_row.phase = 'scope_complete'
       OR request_row.generation <> expected_generation OR request_row.lease_token IS DISTINCT FROM expected_lease_token
       OR request_row.lease_owner IS DISTINCT FROM expected_owner
       OR request_row.lease_expires_at IS NULL OR request_row.lease_expires_at <= statement_timestamp() THEN
        RAISE EXCEPTION 'erasure lease lost' USING ERRCODE = 'P0011';
    END IF;
    RETURN request_row;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_capable(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_operation text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid()
           AND capability.transaction_id = txid_current()
           AND capability.project_id = expected_project_id
           AND capability.request_id = expected_request_id
           AND capability.generation = expected_generation
           AND capability.lease_token = expected_lease_token
           AND capability.operation = expected_operation
    )
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_mint_capability(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, expected_operation text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF expected_operation NOT IN (
        'request_update','receipt_insert','key_destroy','primary_purge','external_work',
        'checkpoint','fence_finalize','project_tombstone','closure_refresh'
    ) THEN
        RAISE EXCEPTION 'erasure invocation denied' USING ERRCODE = 'P0010';
    END IF;
    DELETE FROM public.erasure_execution_capability
     WHERE backend_pid = pg_backend_pid() AND transaction_id <> txid_current();
    INSERT INTO public.erasure_execution_capability (
        backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation
    ) VALUES (
        pg_backend_pid(), txid_current(), expected_project_id, expected_request_id,
        expected_generation, expected_lease_token, expected_operation
    ) ON CONFLICT DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_drop_capability(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_operation text
) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    DELETE FROM public.erasure_execution_capability
     WHERE backend_pid = pg_backend_pid() AND transaction_id = txid_current()
       AND project_id = expected_project_id AND request_id = expected_request_id
       AND generation = expected_generation AND lease_token = expected_lease_token
       AND operation = expected_operation
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_receipt_digest(
    expected_project_id uuid, expected_request_id uuid, expected_step_seq bigint,
    expected_generation integer, expected_step_code text, expected_result text,
    expected_result_code text, expected_attempt integer, expected_affected_rows bigint,
    expected_work_revision bigint, expected_postcondition_digest bytea,
    expected_previous_digest bytea, expected_started_at timestamptz, expected_finished_at timestamptz
) RETURNS bytea LANGUAGE sql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT sha256(convert_to('tracebed.erasure-receipt/v1','UTF8')
        || public.tracebed_erasure_frame(uuid_send(expected_project_id))
        || public.tracebed_erasure_frame(uuid_send(expected_request_id))
        || public.tracebed_erasure_frame(int8send(expected_step_seq))
        || public.tracebed_erasure_frame(int4send(expected_generation))
        || public.tracebed_erasure_frame(convert_to(expected_step_code,'UTF8'))
        || public.tracebed_erasure_frame(convert_to(expected_result,'UTF8'))
        || public.tracebed_erasure_frame(convert_to(expected_result_code,'UTF8'))
        || public.tracebed_erasure_frame(int4send(expected_attempt))
        || public.tracebed_erasure_frame(int8send(expected_affected_rows))
        || public.tracebed_erasure_frame(int8send(expected_work_revision))
        || public.tracebed_erasure_frame(expected_postcondition_digest)
        || CASE WHEN expected_previous_digest IS NULL THEN decode('00','hex')
                ELSE decode('01','hex') || public.tracebed_erasure_frame(expected_previous_digest) END
        || public.tracebed_erasure_frame(timestamptz_send(expected_started_at))
        || public.tracebed_erasure_frame(timestamptz_send(expected_finished_at)))
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_append_receipt(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_step_code text, expected_result text,
    expected_result_code text, expected_affected_rows bigint, expected_work_revision bigint,
    expected_postcondition_digest bytea
) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    request_row public.erasure_request%ROWTYPE;
    next_seq bigint;
    next_attempt integer;
    started_value timestamptz := statement_timestamp();
    finished_value timestamptz := statement_timestamp();
    digest_value bytea;
BEGIN
    IF expected_step_code NOT IN ('fence','crypto','postgres','queue','valkey','trace_store','vector','graph','verify','complete')
       OR expected_result NOT IN ('succeeded','retryable','blocked')
       OR expected_result_code NOT IN (
            'ok','already_absent','not_configured','embedded_primary','closure_changed',
            'dependency_unavailable','dependency_timeout','verification_failed',
            'configuration_mismatch','store_refused','catalog_mismatch','unsafe_path',
            'integrity_failed','operator_resumed'
       ) OR expected_affected_rows < 0 OR expected_work_revision < 1
       OR octet_length(expected_postcondition_digest) <> 32 THEN
        RAISE EXCEPTION 'erasure receipt invocation denied' USING ERRCODE = 'P0010';
    END IF;
    SELECT * INTO request_row FROM public.erasure_request
     WHERE project_id = expected_project_id AND request_id = expected_request_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'erasure receipt invocation denied' USING ERRCODE = 'P0010';
    END IF;
    IF expected_step_code = 'fence' THEN
        IF expected_generation <> 0 OR request_row.next_step_seq <> 1 OR request_row.last_receipt_digest IS NOT NULL THEN
            RAISE EXCEPTION 'erasure receipt invocation denied' USING ERRCODE = 'P0010';
        END IF;
        INSERT INTO public.erasure_execution_capability (
            backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation
        ) VALUES (
            pg_backend_pid(), txid_current(), expected_project_id, expected_request_id,
            0, '00000000-0000-0000-0000-000000000000'::uuid, 'receipt_insert'
        ) ON CONFLICT DO NOTHING;
        INSERT INTO public.erasure_execution_capability (
            backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation
        ) VALUES (
            pg_backend_pid(), txid_current(), expected_project_id, expected_request_id,
            0, '00000000-0000-0000-0000-000000000000'::uuid, 'request_update'
        ) ON CONFLICT DO NOTHING;
    ELSE
        IF expected_generation < 1 OR expected_lease_token IS NULL
           OR NOT public.tracebed_erasure_capable(
               expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert'
           ) THEN
            RAISE EXCEPTION 'erasure receipt invocation denied' USING ERRCODE = 'P0010';
        END IF;
    END IF;
    next_seq := request_row.next_step_seq;
    SELECT count(*)::integer + 1 INTO next_attempt FROM public.erasure_step_receipt
     WHERE project_id = expected_project_id AND request_id = expected_request_id AND step_code = expected_step_code;
    digest_value := public.tracebed_erasure_receipt_digest(
        expected_project_id, expected_request_id, next_seq, expected_generation,
        expected_step_code, expected_result, expected_result_code, next_attempt,
        expected_affected_rows, expected_work_revision, expected_postcondition_digest,
        request_row.last_receipt_digest, started_value, finished_value
    );
    INSERT INTO public.erasure_step_receipt (
        project_id, request_id, step_seq, step_code, attempt, generation, result,
        result_code, affected_rows, work_revision, postcondition_digest,
        previous_receipt_digest, started_at, finished_at, receipt_digest
    ) VALUES (
        expected_project_id, expected_request_id, next_seq, expected_step_code, next_attempt,
        expected_generation, expected_result, expected_result_code, expected_affected_rows,
        expected_work_revision, expected_postcondition_digest, request_row.last_receipt_digest,
        started_value, finished_value, digest_value
    );
    UPDATE public.erasure_request
       SET next_step_seq = next_seq + 1, last_receipt_digest = digest_value,
           updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    IF expected_step_code = 'fence' THEN
        DELETE FROM public.erasure_execution_capability
         WHERE backend_pid = pg_backend_pid() AND transaction_id = txid_current()
           AND project_id = expected_project_id AND request_id = expected_request_id
           AND generation = 0 AND operation = 'receipt_insert';
        DELETE FROM public.erasure_execution_capability
         WHERE backend_pid = pg_backend_pid() AND transaction_id = txid_current()
           AND project_id = expected_project_id AND request_id = expected_request_id
           AND generation = 0 AND operation = 'request_update';
    END IF;
    RETURN digest_value;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_receipt_insert_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.step_code = 'fence' THEN
        IF NEW.generation <> 0 OR NEW.step_seq <> 1 OR NEW.previous_receipt_digest IS NOT NULL
           OR NOT EXISTS (
                SELECT 1 FROM public.erasure_execution_capability AS capability
                 WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
                   AND capability.project_id = NEW.project_id AND capability.request_id = NEW.request_id
                   AND capability.generation = 0 AND capability.operation = 'receipt_insert'
           ) THEN
            RAISE EXCEPTION 'erasure receipt insert denied' USING ERRCODE = '23514';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
           AND capability.project_id = NEW.project_id AND capability.request_id = NEW.request_id
           AND capability.generation = NEW.generation AND capability.operation = 'receipt_insert'
    ) THEN
        RAISE EXCEPTION 'erasure receipt insert denied' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER aa_erasure_step_receipt_insert_guard
    BEFORE INSERT ON public.erasure_step_receipt
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_erasure_receipt_insert_guard();

CREATE OR REPLACE FUNCTION public.tracebed_e3_prepare_fenced_request()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.phase = 'requested' AND NEW.phase = 'fenced' THEN
        NEW.closure_revision := 1;
        NEW.closure_digest := public.tracebed_erasure_closure_digest(NEW.project_id, NEW.request_id, 1);
        NEW.last_code := 'in_progress';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER aa_e3_prepare_fenced_request BEFORE UPDATE ON public.erasure_request
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_e3_prepare_fenced_request();

CREATE OR REPLACE FUNCTION public.tracebed_e3_fence_receipt()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.phase = 'requested' AND NEW.phase = 'fenced' THEN
        PERFORM public.tracebed_erasure_append_receipt(
            NEW.project_id, NEW.request_id, 0, NULL, 'fence', 'succeeded', 'ok', 0,
            NEW.closure_revision, NEW.closure_digest
        );
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER zz_e3_fence_receipt AFTER UPDATE ON public.erasure_request
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_e3_fence_receipt();

CREATE OR REPLACE FUNCTION public.subject_key_enforce_lifecycle() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'subject key deletion denied' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.destroyed_at IS NOT NULL OR octet_length(NEW.wrapped_kek) <> 60 THEN
            RAISE EXCEPTION 'new subject key must be live' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.subject_digest IS DISTINCT FROM OLD.subject_digest
       OR NEW.key_id IS DISTINCT FROM OLD.key_id
       OR NEW.wrap_version IS DISTINCT FROM OLD.wrap_version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'subject key identity is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    IF OLD.destroyed_at IS NOT NULL THEN
        RAISE EXCEPTION 'destroyed subject key is immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.destroyed_at IS NULL OR NOT isfinite(NEW.destroyed_at)
       OR NEW.destroyed_at < OLD.created_at OR NEW.wrapped_kek <> ''::bytea
       OR NEW.subject_tag IS NOT NULL
       OR NOT EXISTS (
            SELECT 1 FROM public.erasure_execution_capability AS capability
             WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
               AND capability.project_id = NEW.project_id AND capability.operation = 'key_destroy'
       ) THEN
        RAISE EXCEPTION 'subject key lifecycle denied' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_work_transition_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'erasure external work is append-only' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
           AND capability.project_id = NEW.project_id AND capability.request_id = NEW.request_id
           AND capability.operation = CASE WHEN TG_TABLE_NAME = 'erasure_external_work'
                                           THEN 'external_work' ELSE 'checkpoint' END
    ) THEN
        RAISE EXCEPTION 'erasure work mutation denied' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.work_id IS DISTINCT FROM OLD.work_id OR NEW.project_id IS DISTINCT FROM OLD.project_id
           OR NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.store_code IS DISTINCT FROM OLD.store_code
           OR NEW.target_kind IS DISTINCT FROM OLD.target_kind OR NEW.target_id IS DISTINCT FROM OLD.target_id
           OR NEW.discovered_revision IS DISTINCT FROM OLD.discovered_revision
           OR (TG_TABLE_NAME = 'erasure_external_work' AND NOT (
                (OLD.state = 'pending' AND NEW.state = 'in_progress')
                OR (OLD.state = 'in_progress' AND NEW.state IN ('in_progress','verified'))
           )) THEN
            RAISE EXCEPTION 'erasure work transition denied' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER erasure_external_work_transition_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.erasure_external_work
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_erasure_work_transition_guard();
CREATE OR REPLACE FUNCTION public.tracebed_erasure_checkpoint_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR NOT EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
           AND capability.project_id = NEW.project_id AND capability.request_id = NEW.request_id
           AND capability.operation = 'checkpoint'
    ) THEN RAISE EXCEPTION 'erasure checkpoint mutation denied' USING ERRCODE = '23514'; END IF;
    IF TG_OP = 'UPDATE' AND (NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.store_code IS DISTINCT FROM OLD.store_code) THEN
        RAISE EXCEPTION 'erasure checkpoint identity denied' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER erasure_store_checkpoint_transition_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.erasure_store_checkpoint
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_erasure_checkpoint_guard();

CREATE OR REPLACE FUNCTION public.tracebed_erasure_verified_must_complete()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.erasure_request
         WHERE project_id = NEW.project_id AND request_id = NEW.request_id AND phase = 'verified'
    ) THEN
        RAISE EXCEPTION 'verified erasure state cannot commit' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER erasure_verified_commit_guard
    AFTER INSERT OR UPDATE ON public.erasure_request DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_erasure_verified_must_complete();

CREATE OR REPLACE FUNCTION public.tracebed_erasure_request_update_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.phase = 'requested' AND NEW.phase = 'fenced' AND session_user = 'tracebed_api' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
           AND capability.project_id = NEW.project_id AND capability.request_id = NEW.request_id
           AND capability.operation = 'request_update'
    ) THEN
        RAISE EXCEPTION 'erasure request mutation denied' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER aa_erasure_request_update_guard BEFORE UPDATE ON public.erasure_request
    FOR EACH ROW EXECUTE FUNCTION public.tracebed_erasure_request_update_guard();

CREATE OR REPLACE FUNCTION public.tracebed_erasure_mint_request_capability(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer, expected_lease_token uuid
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO public.erasure_execution_capability (
        backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation
    ) VALUES (
        pg_backend_pid(), txid_current(), expected_project_id, expected_request_id,
        expected_generation, expected_lease_token, 'request_update'
    ) ON CONFLICT DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_claim_selected(
    selected_request_id uuid, requested_owner text, requested_lease_seconds integer, requested_manifest text[]
) RETURNS TABLE (
    project_id uuid, request_id uuid, scope text, phase text, generation integer,
    lease_token uuid, lease_expires_at timestamptz, closure_revision bigint
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE; new_token uuid;
BEGIN
    IF requested_owner IS NULL OR requested_owner !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$'
       OR requested_lease_seconds NOT BETWEEN 30 AND 900
       OR NOT public.tracebed_erasure_manifest_is_valid(requested_manifest) THEN
        RAISE EXCEPTION 'erasure claim denied' USING ERRCODE = 'P0010';
    END IF;
    SELECT * INTO request_row FROM public.erasure_request AS request_candidate
     WHERE request_candidate.request_id = selected_request_id FOR UPDATE SKIP LOCKED;
    IF NOT FOUND OR request_row.phase = 'scope_complete' OR request_row.disposition = 'operator_blocked'
       OR (request_row.disposition = 'retry_wait' AND request_row.retry_not_before > statement_timestamp())
       OR (request_row.disposition = 'active' AND request_row.lease_token IS NOT NULL
           AND request_row.lease_expires_at > statement_timestamp()) THEN
        RETURN;
    END IF;
    new_token := gen_random_uuid();
    PERFORM public.tracebed_erasure_mint_request_capability(
        request_row.project_id, request_row.request_id, request_row.generation + 1, new_token
    );
    IF request_row.first_started_at IS NOT NULL
       AND (request_row.store_manifest IS DISTINCT FROM requested_manifest
            OR request_row.store_manifest_digest IS DISTINCT FROM public.tracebed_erasure_manifest_digest(requested_manifest)) THEN
        UPDATE public.erasure_request AS request_update
           SET disposition = 'operator_blocked', lease_token = NULL, lease_owner = NULL,
               lease_expires_at = NULL, retry_not_before = NULL,
               last_code = 'operator_action_required',
               updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
         WHERE request_update.project_id = request_row.project_id
           AND request_update.request_id = request_row.request_id;
        RETURN;
    END IF;
    -- The historical E2 transition trigger accepts an expired takeover after
    -- this in-transaction release; no stale lease becomes externally visible.
    IF request_row.lease_token IS NOT NULL THEN
        UPDATE public.erasure_request AS request_update
           SET lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
               updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
         WHERE request_update.project_id = request_row.project_id
           AND request_update.request_id = request_row.request_id;
        SELECT * INTO request_row FROM public.erasure_request AS request_reloaded
         WHERE request_reloaded.project_id = request_row.project_id
           AND request_reloaded.request_id = request_row.request_id FOR UPDATE;
    END IF;
    UPDATE public.erasure_request AS request_update
       SET generation = request_row.generation + 1, lease_token = new_token,
           lease_owner = requested_owner,
           lease_expires_at = statement_timestamp() + make_interval(secs => requested_lease_seconds),
           disposition = 'active', retry_not_before = NULL,
           first_started_at = COALESCE(request_row.first_started_at, statement_timestamp()),
           store_manifest = CASE WHEN request_row.first_started_at IS NULL THEN requested_manifest
                                 ELSE request_row.store_manifest END,
           store_manifest_digest = CASE WHEN request_row.first_started_at IS NULL
                                        THEN public.tracebed_erasure_manifest_digest(requested_manifest)
                                        ELSE request_row.store_manifest_digest END,
           last_code = 'in_progress',
           updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE request_update.project_id = request_row.project_id
       AND request_update.request_id = request_row.request_id;
    RETURN QUERY SELECT row.project_id, row.request_id, row.scope, row.phase, row.generation,
                        row.lease_token, row.lease_expires_at, row.closure_revision
                   FROM public.erasure_request AS row
                  WHERE row.project_id = request_row.project_id AND row.request_id = request_row.request_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_claim_next(
    requested_owner text, requested_lease_seconds integer, requested_manifest text[]
) RETURNS TABLE (
    project_id uuid, request_id uuid, scope text, phase text, generation integer,
    lease_token uuid, lease_expires_at timestamptz, closure_revision bigint
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE candidate uuid;
BEGIN
    PERFORM public.tracebed_erasure_assert_caller();
    IF requested_owner IS NULL OR requested_owner !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$'
       OR requested_lease_seconds NOT BETWEEN 30 AND 900
       OR NOT public.tracebed_erasure_manifest_is_valid(requested_manifest) THEN
        RAISE EXCEPTION 'erasure claim denied' USING ERRCODE = 'P0010';
    END IF;
    SELECT row.request_id INTO candidate FROM public.erasure_request AS row
     WHERE row.phase <> 'requested' AND row.phase <> 'scope_complete'
       AND row.disposition <> 'operator_blocked'
       AND ((row.disposition = 'active' AND (row.lease_token IS NULL OR row.lease_expires_at <= statement_timestamp()))
            OR (row.disposition = 'retry_wait' AND row.retry_not_before <= statement_timestamp()))
     ORDER BY COALESCE(row.retry_not_before, row.requested_at), row.requested_at, row.request_id
     FOR UPDATE SKIP LOCKED LIMIT 1;
    IF candidate IS NULL THEN RETURN; END IF;
    RETURN QUERY SELECT * FROM public.tracebed_erasure_claim_selected(
        candidate, requested_owner, requested_lease_seconds, requested_manifest
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_claim_request(
    selected_request_id uuid, requested_owner text, requested_lease_seconds integer, requested_manifest text[]
) RETURNS TABLE (
    project_id uuid, request_id uuid, scope text, phase text, generation integer,
    lease_token uuid, lease_expires_at timestamptz, closure_revision bigint
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.tracebed_erasure_assert_caller();
    IF selected_request_id IS NULL THEN RAISE EXCEPTION 'erasure claim denied' USING ERRCODE = 'P0010'; END IF;
    RETURN QUERY SELECT * FROM public.tracebed_erasure_claim_selected(
        selected_request_id, requested_owner, requested_lease_seconds, requested_manifest
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_renew(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, requested_lease_seconds integer
) RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE; expiry timestamptz;
BEGIN
    IF requested_lease_seconds NOT BETWEEN 30 AND 900 THEN
        RAISE EXCEPTION 'erasure renew denied' USING ERRCODE = 'P0010';
    END IF;
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        expected_owner, 'request_update'
    );
    expiry := statement_timestamp() + make_interval(secs => requested_lease_seconds);
    UPDATE public.erasure_request
       SET lease_expires_at = expiry, last_code = 'in_progress',
           updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update'
    );
    RETURN expiry;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_release(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE;
BEGIN
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        expected_owner, 'request_update'
    );
    UPDATE public.erasure_request
       SET lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
           updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update'
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_crypto_step(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS TABLE (phase text, affected_rows bigint, closure_revision bigint, result_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE; changed_count bigint;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.phase = 'crypto_erased' OR request_row.phase IN ('primary_purged','external_purged') THEN
        RETURN QUERY SELECT request_row.phase, 0::bigint, request_row.closure_revision, 'already_absent'::text;
        RETURN;
    END IF;
    IF request_row.phase <> 'fenced' THEN RAISE EXCEPTION 'erasure step not actionable' USING ERRCODE = 'P0013'; END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'key_destroy'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'request_update'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'receipt_insert'
    );
    UPDATE public.subject_key AS key_row
       SET destroyed_at = COALESCE(key_row.destroyed_at, statement_timestamp()),
           wrapped_kek = ''::bytea, subject_tag = NULL
     WHERE key_row.project_id = expected_project_id
       AND key_row.destroyed_at IS NULL
       AND (request_row.scope = 'project' OR key_row.subject_digest = request_row.subject_digest);
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    IF request_row.scope = 'project' THEN
        UPDATE public.project SET status = 'deleting'
         WHERE project_id = expected_project_id AND status = 'active';
    END IF;
    UPDATE public.erasure_request
       SET phase = 'crypto_erased', last_code = 'in_progress',
           updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    PERFORM public.tracebed_erasure_append_receipt(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        'crypto', 'succeeded', CASE WHEN changed_count = 0 THEN 'already_absent' ELSE 'ok' END,
        changed_count, request_row.closure_revision,
        sha256(convert_to('tracebed.erasure-crypto/v1','UTF8') || uuid_send(expected_project_id)
               || uuid_send(expected_request_id) || int8send(request_row.closure_revision) || int8send(changed_count))
    );
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'key_destroy');
    RETURN QUERY SELECT 'crypto_erased'::text, changed_count, request_row.closure_revision, 'ok'::text;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_trace_refs_batch(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, expected_revision bigint,
    after_run_id uuid, after_payload_ref text, requested_limit integer
) RETURNS TABLE (run_id uuid, payload_ref text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE;
BEGIN
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF requested_limit NOT BETWEEN 1 AND 10000 OR expected_revision <> request_row.closure_revision
       OR request_row.phase NOT IN ('crypto_erased','primary_purged','external_purged') THEN
        RAISE EXCEPTION 'erasure trace manifest denied' USING ERRCODE = 'P0014';
    END IF;
    RETURN QUERY
    WITH refs AS (
        SELECT DISTINCT index_row.run_id, index_row.payload_ref
          FROM public.trace_index AS index_row
          JOIN public.erase_run_set AS run_set
            ON run_set.project_id = index_row.project_id AND run_set.run_id = index_row.run_id
         WHERE index_row.project_id = expected_project_id AND run_set.request_id = expected_request_id
           AND index_row.payload_ref IS NOT NULL
        UNION
        SELECT DISTINCT index_row.run_id, json_ref.value
          FROM public.trace_index AS index_row
          JOIN public.erase_run_set AS run_set
            ON run_set.project_id = index_row.project_id AND run_set.run_id = index_row.run_id
          CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(index_row.path -> 'payload_refs','[]'::jsonb)) AS json_ref(value)
         WHERE index_row.project_id = expected_project_id AND run_set.request_id = expected_request_id
    )
    SELECT refs.run_id, refs.payload_ref FROM refs
     WHERE after_run_id IS NULL
        OR (refs.run_id, refs.payload_ref) > (after_run_id, after_payload_ref)
     ORDER BY refs.run_id, refs.payload_ref LIMIT requested_limit;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_trace_manifest_digest_for_request(
    expected_project_id uuid, expected_request_id uuid
) RETURNS TABLE (ref_count bigint, manifest_digest bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH refs AS (
        SELECT DISTINCT index_row.run_id, index_row.payload_ref
          FROM public.trace_index AS index_row
          JOIN public.erase_run_set AS run_set
            ON run_set.project_id = index_row.project_id AND run_set.run_id = index_row.run_id
         WHERE index_row.project_id = expected_project_id AND run_set.request_id = expected_request_id
           AND index_row.payload_ref IS NOT NULL
        UNION
        SELECT DISTINCT index_row.run_id, json_ref.value
          FROM public.trace_index AS index_row
          JOIN public.erase_run_set AS run_set
            ON run_set.project_id = index_row.project_id AND run_set.run_id = index_row.run_id
          CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(index_row.path -> 'payload_refs','[]'::jsonb)) AS json_ref(value)
         WHERE index_row.project_id = expected_project_id AND run_set.request_id = expected_request_id
    ), frames AS (
        SELECT uuid_send(expected_project_id) || uuid_send(run_id)
               || int8send(octet_length(convert_to(payload_ref,'UTF8')))
               || convert_to(payload_ref,'UTF8') AS frame FROM refs
    )
    SELECT count(*)::bigint,
           sha256(convert_to('tracebed.erasure-trace-manifest/v1','UTF8') || decode('00','hex')
             || COALESCE((SELECT string_agg(int8send(octet_length(frame)) || frame, ''::bytea ORDER BY frame) FROM frames),''::bytea))
      FROM refs
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_seal_trace_manifest(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, expected_revision bigint,
    supplied_count bigint, supplied_digest bytea
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    request_row public.erasure_request%ROWTYPE;
    actual_count bigint;
    actual_digest bytea;
    manifest_code text;
    materialized_target_count bigint;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.phase NOT IN ('crypto_erased','primary_purged','external_purged')
       OR expected_revision <> request_row.closure_revision
       OR supplied_count < 0 OR octet_length(supplied_digest) <> 32 THEN
        RAISE EXCEPTION 'erasure trace manifest denied' USING ERRCODE = 'P0014';
    END IF;
    SELECT ref_count, manifest_digest INTO actual_count, actual_digest
      FROM public.tracebed_erasure_trace_manifest_digest_for_request(expected_project_id, expected_request_id);
    IF actual_count <> supplied_count OR actual_digest IS DISTINCT FROM supplied_digest THEN
        RAISE EXCEPTION 'erasure trace manifest mismatch' USING ERRCODE = 'P0012';
    END IF;
    SELECT code INTO manifest_code FROM unnest(request_row.store_manifest) AS value(code)
     WHERE code IN ('trace_fs_v1','trace_s3_v1');
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'checkpoint'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'external_work'
    );
    -- A revision change invalidates the external proof.  Re-running a delete
    -- and independent absence verification is conservative for trace targets
    -- too; it avoids relying on a client-side distinction after a crash.
    UPDATE public.erasure_external_work
       SET discovered_revision = expected_revision, state = 'pending',
           claimed_generation = NULL, claimed_token = NULL, started_at = NULL,
           verified_at = NULL, affected_rows = NULL, last_result_code = NULL,
           postcondition_digest = NULL
     WHERE project_id = expected_project_id AND request_id = expected_request_id
       AND store_code = manifest_code AND discovered_revision < expected_revision;
    INSERT INTO public.erasure_external_work (project_id, request_id, store_code, target_kind, target_id, discovered_revision)
    SELECT expected_project_id, expected_request_id, manifest_code, 'run', run_set.run_id, expected_revision
      FROM public.erase_run_set AS run_set
     WHERE run_set.project_id = expected_project_id AND run_set.request_id = expected_request_id
       AND request_row.scope = 'subject'
    UNION ALL
    SELECT expected_project_id, expected_request_id, manifest_code, 'project', NULL, expected_revision
     WHERE request_row.scope = 'project'
    ON CONFLICT (project_id, request_id, store_code, target_kind, target_id) DO NOTHING;
    SELECT count(*) INTO materialized_target_count
      FROM public.erasure_external_work
     WHERE project_id = expected_project_id AND request_id = expected_request_id
       AND store_code = manifest_code AND discovered_revision = expected_revision;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'external_work');
    INSERT INTO public.erasure_store_checkpoint (
        project_id, request_id, store_code, prepared_revision, target_count, target_manifest_digest
    ) VALUES (
        expected_project_id, expected_request_id, manifest_code, expected_revision,
        materialized_target_count, actual_digest
    ) ON CONFLICT (project_id, request_id, store_code) DO UPDATE
      SET prepared_revision = EXCLUDED.prepared_revision, target_count = EXCLUDED.target_count,
          target_manifest_digest = EXCLUDED.target_manifest_digest,
          verified_revision = NULL, postcondition_digest = NULL, result_code = NULL, verified_at = NULL
      WHERE public.erasure_store_checkpoint.prepared_revision < EXCLUDED.prepared_revision;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'checkpoint');
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_prepare_primary(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS TABLE (closure_revision bigint, pending_external bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE; code_value text; target_count bigint;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.phase NOT IN ('crypto_erased','primary_purged','external_purged') THEN
        RAISE EXCEPTION 'erasure primary preparation denied' USING ERRCODE = 'P0013';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.erasure_store_checkpoint
         WHERE project_id = expected_project_id AND request_id = expected_request_id
           AND store_code IN ('trace_fs_v1','trace_s3_v1') AND prepared_revision = request_row.closure_revision
    ) THEN
        RAISE EXCEPTION 'erasure trace manifest not sealed' USING ERRCODE = 'P0014';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'checkpoint'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner, 'external_work'
    );
    FOREACH code_value IN ARRAY request_row.store_manifest LOOP
        IF code_value NOT IN ('trace_fs_v1','trace_s3_v1') THEN
            target_count := 1;
            UPDATE public.erasure_external_work
               SET discovered_revision = request_row.closure_revision, state = 'pending',
                   claimed_generation = NULL, claimed_token = NULL, started_at = NULL,
                   verified_at = NULL, affected_rows = NULL, last_result_code = NULL,
                   postcondition_digest = NULL
             WHERE project_id = expected_project_id AND request_id = expected_request_id
               AND store_code = code_value AND discovered_revision < request_row.closure_revision;
            INSERT INTO public.erasure_store_checkpoint (
                project_id, request_id, store_code, prepared_revision, target_count, target_manifest_digest
            ) VALUES (
                expected_project_id, expected_request_id, code_value, request_row.closure_revision,
                target_count, sha256(convert_to('tracebed.erasure-store-target/v1','UTF8') || convert_to(code_value,'UTF8'))
            ) ON CONFLICT (project_id, request_id, store_code) DO UPDATE
                 SET prepared_revision = EXCLUDED.prepared_revision, target_count = EXCLUDED.target_count,
                     target_manifest_digest = EXCLUDED.target_manifest_digest,
                     verified_revision = NULL, postcondition_digest = NULL, result_code = NULL, verified_at = NULL
                 WHERE public.erasure_store_checkpoint.prepared_revision < EXCLUDED.prepared_revision;
            INSERT INTO public.erasure_external_work (
                project_id, request_id, store_code, target_kind, target_id, discovered_revision
            ) VALUES (
                expected_project_id, expected_request_id, code_value, 'project', NULL, request_row.closure_revision
            ) ON CONFLICT (project_id, request_id, store_code, target_kind, target_id) DO NOTHING;
        END IF;
    END LOOP;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'external_work');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'checkpoint');
    SELECT count(*) INTO pending_external FROM public.erasure_external_work
     WHERE project_id = expected_project_id AND request_id = expected_request_id
       AND discovered_revision = request_row.closure_revision AND state <> 'verified';
    RETURN QUERY SELECT request_row.closure_revision, pending_external;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_primary_remaining(
    expected_project_id uuid, expected_request_id uuid
) RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH request_scope AS (
        SELECT scope, subject_digest
          FROM public.erasure_request
         WHERE project_id = expected_project_id AND request_id = expected_request_id
    ), count_vector(required_rows) AS (
        SELECT count(*) FROM public.work_queue AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.dead_letter AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.trace_learning_job AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.outcome_event AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.injection_log AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.retrieval_event AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.blackboard_entry AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.trace_index AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.run_owner AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.memory_status_log AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set WHERE mem_set.project_id = expected_project_id
                         AND mem_set.request_id = expected_request_id AND mem_set.memory_id = row.memory_id))
        UNION ALL SELECT count(*) FROM public.memory_q_update AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set WHERE mem_set.project_id = expected_project_id
                         AND mem_set.request_id = expected_request_id AND mem_set.memory_id = row.memory_id))
        UNION ALL SELECT count(*) FROM public.review_queue AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set WHERE mem_set.project_id = expected_project_id
                         AND mem_set.request_id = expected_request_id AND mem_set.memory_id = row.memory_id))
        UNION ALL SELECT count(*) FROM public.memory_link AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set WHERE mem_set.project_id = expected_project_id
                         AND mem_set.request_id = expected_request_id
                         AND mem_set.memory_id IN (row.src_id, row.dst_id)))
        UNION ALL SELECT count(*) FROM public.run_memory_binding AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id)
            OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set WHERE mem_set.project_id = expected_project_id
                         AND mem_set.request_id = expected_request_id AND mem_set.memory_id = row.memory_id))
        UNION ALL SELECT count(*) FROM public.memory_item AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR request_row.subject_digest = ANY(row.subject_digests)
            OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set WHERE mem_set.project_id = expected_project_id
                         AND mem_set.request_id = expected_request_id AND mem_set.memory_id = row.id))
        UNION ALL SELECT count(*) FROM public.trace_subject AS row CROSS JOIN request_scope AS request_row
         WHERE row.project_id = expected_project_id AND (request_row.scope = 'project'
            OR row.subject_digest = request_row.subject_digest
            OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set WHERE run_set.project_id = expected_project_id
                         AND run_set.request_id = expected_request_id AND run_set.run_id = row.run_id))
        UNION ALL SELECT count(*) FROM public.derived_state WHERE project_id = expected_project_id
        UNION ALL SELECT count(*) FROM public.invalidation_event WHERE project_id = expected_project_id
        UNION ALL SELECT count(*) FROM public.killswitch_state CROSS JOIN request_scope AS request_row
         WHERE project_id = expected_project_id
           AND (request_row.scope = 'project' OR evidence IS NOT NULL)
        UNION ALL SELECT count(*) FROM public.project_config CROSS JOIN request_scope AS request_row
         WHERE project_id = expected_project_id AND request_row.scope = 'project'
        UNION ALL SELECT count(*) FROM public.agent_type_config CROSS JOIN request_scope AS request_row
         WHERE project_id = expected_project_id AND request_row.scope = 'project'
    )
    SELECT COALESCE(sum(required_rows), 0)::bigint FROM count_vector
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_primary_batch(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text, requested_limit integer
) RETURNS TABLE (
    batch_code text, affected_rows bigint, remaining bigint,
    closure_revision bigint, postcondition_digest bytea
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE request_row public.erasure_request%ROWTYPE; changed_count bigint := 0; left_count bigint; digest_value bytea;
BEGIN
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF requested_limit NOT BETWEEN 1 AND 10000 OR request_row.phase NOT IN ('crypto_erased','primary_purged','external_purged') THEN
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
    -- Fixed branch vocabulary: no caller-provided relation text is ever used.
    DELETE FROM public.work_queue AS row WHERE row.ctid IN (
        SELECT candidate.ctid FROM public.work_queue AS candidate
         WHERE candidate.project_id = expected_project_id AND (
             EXISTS (SELECT 1 FROM public.erasure_request AS request_check
                      WHERE request_check.project_id = expected_project_id AND request_check.request_id = expected_request_id
                        AND request_check.scope = 'project')
             OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                        WHERE run_set.project_id = expected_project_id AND run_set.request_id = expected_request_id
                          AND run_set.run_id = candidate.run_id)
         ) LIMIT requested_limit
    );
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    IF changed_count = 0 THEN
        DELETE FROM public.dead_letter AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.dead_letter AS candidate
             WHERE candidate.project_id = expected_project_id AND (
                 EXISTS (SELECT 1 FROM public.erasure_request AS request_check
                          WHERE request_check.project_id = expected_project_id AND request_check.request_id = expected_request_id
                            AND request_check.scope = 'project')
                 OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id)
             ) LIMIT requested_limit
        ); GET DIAGNOSTICS changed_count = ROW_COUNT;
    END IF;
    IF changed_count = 0 THEN
        DELETE FROM public.trace_index AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.trace_index AS candidate
             WHERE candidate.project_id = expected_project_id AND (
                 EXISTS (SELECT 1 FROM public.erasure_request AS request_check
                          WHERE request_check.project_id = expected_project_id AND request_check.request_id = expected_request_id
                            AND request_check.scope = 'project')
                 OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id)
             ) LIMIT requested_limit
        ); GET DIAGNOSTICS changed_count = ROW_COUNT;
    END IF;
    IF changed_count = 0 THEN
        DELETE FROM public.trace_subject AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.trace_subject AS candidate
             WHERE candidate.project_id = expected_project_id AND (
                 EXISTS (SELECT 1 FROM public.erasure_request AS request_check
                          WHERE request_check.project_id = expected_project_id AND request_check.request_id = expected_request_id
                            AND request_check.scope = 'project')
                 OR EXISTS (SELECT 1 FROM public.erase_run_set AS run_set
                            WHERE run_set.project_id = expected_project_id AND run_set.request_id = expected_request_id
                              AND run_set.run_id = candidate.run_id)
             ) LIMIT requested_limit
        ); GET DIAGNOSTICS changed_count = ROW_COUNT;
    END IF;
    IF changed_count = 0 THEN
        DELETE FROM public.memory_link AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.memory_link AS candidate
             WHERE candidate.project_id = expected_project_id AND (
                 EXISTS (SELECT 1 FROM public.erasure_request AS request_check
                          WHERE request_check.project_id = expected_project_id AND request_check.request_id = expected_request_id
                            AND request_check.scope = 'project')
                 OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id AND mem_set.request_id = expected_request_id
                              AND (mem_set.memory_id = candidate.src_id OR mem_set.memory_id = candidate.dst_id))
             ) LIMIT requested_limit
        ); GET DIAGNOSTICS changed_count = ROW_COUNT;
    END IF;
    IF changed_count = 0 THEN
        DELETE FROM public.memory_item AS row WHERE row.ctid IN (
            SELECT candidate.ctid FROM public.memory_item AS candidate
             WHERE candidate.project_id = expected_project_id AND (
                 EXISTS (SELECT 1 FROM public.erasure_request AS request_check
                          WHERE request_check.project_id = expected_project_id AND request_check.request_id = expected_request_id
                            AND request_check.scope = 'project')
                 OR EXISTS (SELECT 1 FROM public.erase_mem_set AS mem_set
                            WHERE mem_set.project_id = expected_project_id AND mem_set.request_id = expected_request_id
                              AND mem_set.memory_id = candidate.id)
             ) LIMIT requested_limit
        ); GET DIAGNOSTICS changed_count = ROW_COUNT;
    END IF;
    IF changed_count = 0 THEN
        DELETE FROM public.derived_state WHERE project_id = expected_project_id;
        GET DIAGNOSTICS changed_count = ROW_COUNT;
        DELETE FROM public.invalidation_event WHERE project_id = expected_project_id;
        UPDATE public.killswitch_state SET evidence = NULL WHERE project_id = expected_project_id AND evidence IS NOT NULL;
    END IF;
    SELECT public.tracebed_erasure_primary_remaining(expected_project_id, expected_request_id) INTO left_count;
    digest_value := sha256(convert_to('tracebed.erasure-primary/v1','UTF8') || uuid_send(expected_project_id)
      || uuid_send(expected_request_id) || int8send(request_row.closure_revision) || int8send(left_count));
    IF left_count = 0 AND request_row.phase = 'crypto_erased' THEN
        UPDATE public.erasure_request SET phase = 'primary_purged', last_code = 'in_progress',
             updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
         WHERE project_id = expected_project_id AND request_id = expected_request_id;
        PERFORM public.tracebed_erasure_append_receipt(
            expected_project_id, expected_request_id, expected_generation, expected_lease_token,
            'postgres','succeeded','ok',changed_count,request_row.closure_revision,digest_value
        );
    END IF;
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update');
    PERFORM public.tracebed_erasure_drop_capability(expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'primary_purge');
    RETURN QUERY SELECT 'postgres'::text, changed_count, left_count, request_row.closure_revision, digest_value;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_runtime_erasure_write_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE project_value uuid;
BEGIN
    project_value := CASE WHEN TG_OP = 'DELETE'
        THEN (pg_catalog.to_jsonb(OLD) ->> 'project_id')::uuid
        ELSE (pg_catalog.to_jsonb(NEW) ->> 'project_id')::uuid END;
    IF project_value IS NULL THEN RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002'; END IF;
    -- The transaction-bound capability is the only E3 exception.  It is
    -- minted after exact lease authentication and cannot cross a backend/xid.
    IF EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
           AND capability.project_id = project_value
           AND capability.operation IN ('primary_purge','key_destroy','fence_finalize','project_tombstone')
    ) THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF session_user = 'tracebed_owner' THEN RETURN COALESCE(NEW, OLD); END IF;
    IF session_user NOT IN ('tracebed_api','tracebed_worker')
       OR (session_user = 'tracebed_api' AND NOT pg_catalog.pg_has_role(session_user,'tracebed_api_group','member'))
       OR (session_user = 'tracebed_worker' AND NOT pg_catalog.pg_has_role(session_user,'tracebed_worker_group','member'))
       OR pg_catalog.current_setting('tracebed.project_id', true) IS DISTINCT FROM project_value::text
       OR NOT pg_catalog.pg_try_advisory_xact_lock_shared(
           pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || project_value::text, 0)
       ) THEN RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002'; END IF;
    PERFORM 1 FROM public.erasure_request AS request_row
     WHERE request_row.project_id = project_value
       AND (request_row.scope = 'project' OR request_row.disposition <> 'scope_complete') FOR SHARE;
    IF FOUND THEN
        IF (TG_TABLE_NAME = 'trace_subject' OR EXISTS (
                SELECT 1 FROM pg_catalog.pg_inherits AS inheritance
                 JOIN pg_catalog.pg_class AS parent ON parent.oid = inheritance.inhparent
                 JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = parent.relnamespace
                 WHERE inheritance.inhrelid = TG_RELID AND namespace.nspname = 'public' AND parent.relname = 'trace_subject'
            )) AND TG_OP IN ('INSERT','DELETE')
           AND (TG_OP = 'INSERT' OR (pg_catalog.to_jsonb(OLD) ->> 'subject_digest')::bytea
                = public.tracebed_subject_digest(project_value,'__project__'))
           AND EXISTS (
                SELECT 1 FROM public.erasure_late_bind_capability AS capability
                 WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
                   AND capability.project_id = project_value
                   AND capability.run_id = COALESCE((pg_catalog.to_jsonb(NEW) ->> 'run_id')::uuid,
                                                    (pg_catalog.to_jsonb(OLD) ->> 'run_id')::uuid)
           ) THEN RETURN COALESCE(NEW, OLD); END IF;
        RAISE EXCEPTION 'erasure fence refused activity' USING ERRCODE = 'P0002';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION public.trace_index_enforce_terminal_immutability() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
           AND capability.project_id = COALESCE(NEW.project_id, OLD.project_id)
           AND capability.operation = 'primary_purge'
    ) THEN RETURN COALESCE(NEW, OLD); END IF;
    IF TG_OP = 'DELETE' THEN
        IF OLD.outcome_status IN ('ok','error','cancelled') THEN
            RAISE EXCEPTION 'terminal trace index rows cannot be deleted' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.outcome_status IN ('ok','error','cancelled') THEN
        IF session_user = 'tracebed_api' AND current_user = 'tracebed_owner'
           AND pg_catalog.pg_has_role(session_user,'tracebed_api_group','member')
           AND (pg_catalog.to_jsonb(NEW) - 'subject_digests') IS NOT DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'subject_digests')
           AND (OLD.subject_digests <@ NEW.subject_digests OR OLD.subject_digests IS NOT DISTINCT FROM ARRAY[
                public.tracebed_subject_digest(NEW.project_id,'__project__')
           ]::bytea[])
           AND NEW.subject_digests IS NOT DISTINCT FROM COALESCE((
               SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
                 FROM public.trace_subject AS binding
                WHERE binding.project_id = NEW.project_id AND binding.run_id = NEW.run_id
           ), ARRAY[public.tracebed_subject_digest(NEW.project_id,'__project__')]) THEN RETURN NEW; END IF;
        RAISE EXCEPTION 'terminal trace index rows are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.run_owner_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid() AND capability.transaction_id = txid_current()
           AND capability.project_id = COALESCE(NEW.project_id, OLD.project_id)
           AND capability.operation = 'primary_purge'
    ) THEN RETURN COALESCE(NEW, OLD); END IF;
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'run owners cannot be deleted' USING ERRCODE = '23514'; END IF;
    IF session_user = 'tracebed_api' AND current_user = 'tracebed_owner'
       AND pg_catalog.pg_has_role(session_user,'tracebed_api_group','member')
       AND (pg_catalog.to_jsonb(NEW) - 'subject_digests') IS NOT DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'subject_digests')
       AND (OLD.subject_digests <@ NEW.subject_digests OR OLD.subject_digests IS NOT DISTINCT FROM ARRAY[
            public.tracebed_subject_digest(NEW.project_id,'__project__')
       ]::bytea[])
       AND NEW.subject_digests IS NOT DISTINCT FROM COALESCE((
            SELECT array_agg(binding.subject_digest ORDER BY binding.subject_digest)
              FROM public.trace_subject AS binding
             WHERE binding.project_id = NEW.project_id AND binding.run_id = NEW.run_id
       ), ARRAY[public.tracebed_subject_digest(NEW.project_id,'__project__')]) THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'run owners are immutable' USING ERRCODE = '23514';
END;
$$;

-- A late bind is the sole post-fence closure expansion.  It runs under the
-- API's existing project-shared lock, locks the request row once, and stamps
-- only rows inserted by that bind.  All prior primary/checkpoint proofs are
-- thereby revision-stale without mutating historical closure evidence.
CREATE OR REPLACE FUNCTION public.tracebed_erasure_refresh_late_closure(
    expected_project_id uuid, expected_request_id uuid,
    inserted_run_ids uuid[], inserted_memory_ids uuid[]
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    request_row public.erasure_request%ROWTYPE;
    next_revision bigint;
    cap_token uuid := '00000000-0000-0000-0000-000000000000'::uuid;
BEGIN
    IF session_user IS DISTINCT FROM 'tracebed_api'
       OR NOT pg_catalog.pg_has_role(session_user, 'tracebed_api_group', 'member')
       OR expected_project_id IS NULL OR expected_request_id IS NULL
       OR (cardinality(inserted_run_ids) = 0 AND cardinality(inserted_memory_ids) = 0) THEN
        RAISE EXCEPTION 'erasure late closure denied' USING ERRCODE = 'P0010';
    END IF;

    SELECT * INTO request_row
      FROM public.erasure_request
     WHERE project_id = expected_project_id AND request_id = expected_request_id
     FOR UPDATE;
    IF NOT FOUND OR request_row.scope <> 'subject'
       OR request_row.phase = 'scope_complete'
       OR request_row.disposition = 'scope_complete' THEN
        RAISE EXCEPTION 'erasure late closure denied' USING ERRCODE = 'P0014';
    END IF;

    next_revision := request_row.closure_revision + 1;
    INSERT INTO public.erasure_execution_capability (
        backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation
    ) VALUES (
        pg_backend_pid(), txid_current(), expected_project_id, expected_request_id,
        request_row.generation, cap_token, 'closure_refresh'
    ) ON CONFLICT DO NOTHING;
    INSERT INTO public.erasure_execution_capability (
        backend_pid, transaction_id, project_id, request_id, generation, lease_token, operation
    ) VALUES (
        pg_backend_pid(), txid_current(), expected_project_id, expected_request_id,
        request_row.generation, cap_token, 'request_update'
    ) ON CONFLICT DO NOTHING;

    UPDATE public.erase_run_set
       SET discovered_revision = next_revision
     WHERE project_id = expected_project_id AND request_id = expected_request_id
       AND run_id = ANY(COALESCE(inserted_run_ids, '{}'::uuid[]));
    UPDATE public.erase_mem_set
       SET discovered_revision = next_revision
     WHERE project_id = expected_project_id AND request_id = expected_request_id
       AND memory_id = ANY(COALESCE(inserted_memory_ids, '{}'::uuid[]));
    UPDATE public.erasure_request
       SET closure_revision = next_revision,
           closure_digest = public.tracebed_erasure_closure_digest(
               expected_project_id, expected_request_id, next_revision
           ),
           last_code = 'in_progress',
           updated_at = GREATEST(clock_timestamp(), request_row.updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;

    DELETE FROM public.erasure_execution_capability
     WHERE backend_pid = pg_backend_pid() AND transaction_id = txid_current()
       AND project_id = expected_project_id AND request_id = expected_request_id
       AND generation = request_row.generation AND lease_token = cap_token
       AND operation IN ('closure_refresh', 'request_update');
    RETURN next_revision;
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_set_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND (pg_catalog.to_jsonb(NEW) - 'discovered_revision')
             IS NOT DISTINCT FROM (pg_catalog.to_jsonb(OLD) - 'discovered_revision')
       AND NEW.discovered_revision > OLD.discovered_revision
       AND EXISTS (
            SELECT 1 FROM public.erasure_execution_capability AS capability
             WHERE capability.backend_pid = pg_backend_pid()
               AND capability.transaction_id = txid_current()
               AND capability.project_id = NEW.project_id
               AND capability.request_id = NEW.request_id
               AND capability.operation = 'closure_refresh'
       ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'erasure closure sets are append-only' USING ERRCODE = '23514';
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_work_transition_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'erasure external work is append-only' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.erasure_execution_capability AS capability
         WHERE capability.backend_pid = pg_backend_pid()
           AND capability.transaction_id = txid_current()
           AND capability.project_id = NEW.project_id
           AND capability.request_id = NEW.request_id
           AND capability.operation = 'external_work'
    ) THEN
        RAISE EXCEPTION 'erasure work mutation denied' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.work_id IS DISTINCT FROM OLD.work_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.store_code IS DISTINCT FROM OLD.store_code
       OR NEW.target_kind IS DISTINCT FROM OLD.target_kind
       OR NEW.target_id IS DISTINCT FROM OLD.target_id THEN
        RAISE EXCEPTION 'erasure work transition denied' USING ERRCODE = '23514';
    END IF;
    IF NEW.discovered_revision = OLD.discovered_revision
       AND ((OLD.state = 'pending' AND NEW.state = 'in_progress')
            OR (OLD.state = 'in_progress' AND NEW.state IN ('in_progress','verified'))) THEN
        RETURN NEW;
    END IF;
    -- A new closure revision can make a previously verified project-wide
    -- adapter proof stale.  It is reset only by a live lease routine; no
    -- historical target identity is replaced or deleted.
    IF NEW.discovered_revision > OLD.discovered_revision
       AND NEW.state = 'pending'
       AND NEW.claimed_generation IS NULL AND NEW.claimed_token IS NULL
       AND NEW.started_at IS NULL AND NEW.verified_at IS NULL
       AND NEW.affected_rows IS NULL AND NEW.last_result_code IS NULL
       AND NEW.postcondition_digest IS NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'erasure work transition denied' USING ERRCODE = '23514';
END;
$$;

-- Every destructive E3 operation acquires this project-wide exclusive lock
-- before it locks the request row.  Claims and renewals deliberately do not
-- use it: a claim is global/short and the heartbeat must only wait on its
-- request row.  The helper is private and source-profiled so an accidental
-- lock-order regression is catalog-visible.
CREATE OR REPLACE FUNCTION public.tracebed_erasure_lock_project(expected_project_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF expected_project_id IS NULL THEN
        RAISE EXCEPTION 'erasure invocation denied' USING ERRCODE = 'P0010';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('tracebed.erasure.project/v1:' || expected_project_id::text, 0)
    );
END;
$$;

-- The generic partition library is intentionally not an erasure authority.
-- Resolve every purgeable attached leaf from the catalog and exact LIST bound
-- here, under the live E3 lease.  ``subject_key`` is deliberately excluded:
-- destroyed key rows are durable tombstones and survive a project deletion.
-- A renamed genuine public child is accepted; ambiguous, cross-schema,
-- wrong-bound, or canonical-homonym shapes block.
CREATE OR REPLACE FUNCTION public.tracebed_erasure_drop_project_partitions(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    request_row public.erasure_request%ROWTYPE;
    parent_name text;
    parent_oid oid;
    child_oid oid;
    child_schema text;
    child_name text;
    child_kind "char";
    canonical_oid oid;
    exact_child_count integer;
    already_dropped boolean;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.scope <> 'project'
       OR request_row.phase NOT IN ('crypto_erased','primary_purged','external_purged')
       OR NOT public.tracebed_erasure_capable(
            expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'primary_purge'
       ) THEN
        RAISE EXCEPTION 'erasure project catalog denied' USING ERRCODE = 'P0013';
    END IF;
    already_dropped := request_row.phase IN ('primary_purged','external_purged');
    FOREACH parent_name IN ARRAY ARRAY[
        'memory_item','memory_link','derived_state','trace_index','trace_subject',
        'outcome_event','injection_log','retrieval_event','blackboard_entry',
        'invalidation_event','spend_ledger','review_queue','memory_status_log',
        'memory_q_update','trace_learning_job','run_owner','subject_fence','run_fence',
        'erase_run_set','erase_mem_set','run_memory_binding'
    ] LOOP
        SELECT relation.oid INTO parent_oid
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public' AND relation.relname = parent_name
           AND relation.relkind = 'p';
        IF parent_oid IS NULL THEN
            RAISE EXCEPTION 'erasure project catalog mismatch' USING ERRCODE = 'P0013';
        END IF;
        SELECT count(*)::integer INTO exact_child_count
          FROM pg_catalog.pg_inherits AS inheritance
          JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
         WHERE inheritance.inhparent = parent_oid
           AND pg_catalog.pg_get_expr(child.relpartbound, child.oid)
               = pg_catalog.format('FOR VALUES IN (%L)', expected_project_id::text);
        IF exact_child_count > 1 THEN
            RAISE EXCEPTION 'erasure project catalog mismatch' USING ERRCODE = 'P0013';
        END IF;
        IF exact_child_count = 0 THEN
            SELECT relation.oid INTO canonical_oid
              FROM pg_catalog.pg_class AS relation
              JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = 'public'
               AND relation.relname = parent_name || '_p_' || replace(expected_project_id::text, '-', '');
            IF canonical_oid IS NOT NULL OR NOT already_dropped THEN
                RAISE EXCEPTION 'erasure project catalog mismatch' USING ERRCODE = 'P0013';
            END IF;
            CONTINUE;
        END IF;
        SELECT child.oid, namespace.nspname, child.relname, child.relkind
          INTO child_oid, child_schema, child_name, child_kind
          FROM pg_catalog.pg_inherits AS inheritance
          JOIN pg_catalog.pg_class AS child ON child.oid = inheritance.inhrelid
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = child.relnamespace
         WHERE inheritance.inhparent = parent_oid
           AND pg_catalog.pg_get_expr(child.relpartbound, child.oid)
               = pg_catalog.format('FOR VALUES IN (%L)', expected_project_id::text);
        IF child_oid IS NULL OR child_schema <> 'public' OR child_kind <> 'r' THEN
            RAISE EXCEPTION 'erasure project catalog mismatch' USING ERRCODE = 'P0013';
        END IF;
        SELECT relation.oid INTO canonical_oid
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname = parent_name || '_p_' || replace(expected_project_id::text, '-', '');
        IF canonical_oid IS NOT NULL AND canonical_oid <> child_oid THEN
            RAISE EXCEPTION 'erasure project catalog mismatch' USING ERRCODE = 'P0013';
        END IF;
        EXECUTE pg_catalog.format('ALTER TABLE public.%I DETACH PARTITION public.%I', parent_name, child_name);
        EXECUTE pg_catalog.format('DROP TABLE public.%I', child_name);
    END LOOP;
END;
$$;

-- Keep the public E3 batch signature deliberately small while retaining a
-- fixed, auditable branch for every attributed family.  The executor never
-- supplies a relation name or predicate; the only variable is its bounded
-- batch size.  Each branch may consume at most that many rows, making renews
-- possible between database transactions.
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

-- E3's project tombstone is the one narrow exception to the authority-root
-- immutability guards.  A capability is transaction-bound to an exact live
-- lease; outside it these retain their ordinary one-way/immutable behavior.
CREATE OR REPLACE FUNCTION public.project_enforce_lifecycle() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND EXISTS (
            SELECT 1 FROM public.erasure_execution_capability AS capability
             WHERE capability.backend_pid = pg_backend_pid()
               AND capability.transaction_id = txid_current()
               AND capability.project_id = NEW.project_id
               AND capability.operation = 'project_tombstone'
       )
       AND OLD.status = 'deleting' AND NEW.status = 'deleted'
       AND NEW.name = 'deleted-project' AND NEW.retention_policy IS NULL
       AND NEW.provisioning_key_hash IS NULL AND NEW.provisioning_request_hash IS NULL
       AND NEW.project_id IS NOT DISTINCT FROM OLD.project_id
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        NEW.deleted_at := statement_timestamp();
        RETURN NEW;
    END IF;
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
        RAISE EXCEPTION 'project metadata may only change while active or suspended' USING ERRCODE = '23514';
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

CREATE OR REPLACE FUNCTION public.agent_type_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.agent_type_id IS NOT DISTINCT FROM OLD.agent_type_id
       AND NEW.project_id IS NOT DISTINCT FROM OLD.project_id
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
       AND NEW.name = 'deleted-agent:' || OLD.agent_type_id::text
       AND EXISTS (
            SELECT 1 FROM public.erasure_execution_capability AS capability
             WHERE capability.backend_pid = pg_backend_pid()
               AND capability.transaction_id = txid_current()
               AND capability.project_id = NEW.project_id
               AND capability.operation = 'project_tombstone'
       ) THEN
        RETURN NEW;
    END IF;
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

CREATE OR REPLACE FUNCTION public.principal_enforce_immutability() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.principal_id IS NOT DISTINCT FROM OLD.principal_id
       AND NEW.kind IS NOT DISTINCT FROM OLD.kind
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
       AND NEW.external_ref = 'deleted-principal:' || OLD.principal_id::text
       AND NEW.key_hash IS NULL AND NEW.revoked_at IS NOT NULL
       AND EXISTS (
            SELECT 1
              FROM public.agent_registration AS registration
              JOIN public.erasure_execution_capability AS capability
                ON capability.project_id = registration.project_id
             WHERE registration.principal_id = NEW.principal_id
               AND capability.backend_pid = pg_backend_pid()
               AND capability.transaction_id = txid_current()
               AND capability.operation = 'project_tombstone'
       ) THEN
        RETURN NEW;
    END IF;
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

CREATE OR REPLACE FUNCTION public.tracebed_erasure_tombstone_project(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    request_row public.erasure_request%ROWTYPE;
    tombstoned_count bigint;
BEGIN
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.scope <> 'project' OR request_row.phase <> 'external_purged' THEN
        RAISE EXCEPTION 'erasure project tombstone denied' USING ERRCODE = 'P0013';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        expected_owner, 'project_tombstone'
    );
    UPDATE public.principal_grant
       SET revoked_at = COALESCE(revoked_at, statement_timestamp())
     WHERE project_id = expected_project_id AND revoked_at IS NULL;
    UPDATE public.agent_registration
       SET revoked_at = COALESCE(revoked_at, statement_timestamp())
     WHERE project_id = expected_project_id AND revoked_at IS NULL;
    UPDATE public.agent_type
       SET name = 'deleted-agent:' || agent_type_id::text
     WHERE project_id = expected_project_id
       AND name IS DISTINCT FROM 'deleted-agent:' || agent_type_id::text;
    UPDATE public.principal AS principal_row
       SET revoked_at = COALESCE(principal_row.revoked_at, statement_timestamp()),
           external_ref = 'deleted-principal:' || principal_row.principal_id::text,
           key_hash = NULL
     WHERE EXISTS (
            SELECT 1 FROM public.agent_registration AS registration
             WHERE registration.principal_id = principal_row.principal_id
               AND registration.project_id = expected_project_id
       )
       AND NOT EXISTS (
            SELECT 1 FROM public.erasure_request AS actor_request
             WHERE actor_request.requested_principal_id = principal_row.principal_id
       )
       AND (principal_row.revoked_at IS NULL OR principal_row.key_hash IS NOT NULL
            OR principal_row.external_ref IS DISTINCT FROM 'deleted-principal:' || principal_row.principal_id::text);
    UPDATE public.project
       SET name = 'deleted-project', retention_policy = NULL,
           provisioning_key_hash = NULL, provisioning_request_hash = NULL,
           status = 'deleted'
     WHERE project_id = expected_project_id AND status = 'deleting';
    GET DIAGNOSTICS tombstoned_count = ROW_COUNT;
    IF tombstoned_count = 0 AND NOT EXISTS (
        SELECT 1 FROM public.project
         WHERE project_id = expected_project_id AND status = 'deleted'
           AND name = 'deleted-project' AND retention_policy IS NULL
           AND provisioning_key_hash IS NULL AND provisioning_request_hash IS NULL
    ) THEN
        RAISE EXCEPTION 'erasure project tombstone denied' USING ERRCODE = 'P0013';
    END IF;
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'project_tombstone'
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.tracebed_erasure_verify_and_complete(
    expected_project_id uuid, expected_request_id uuid, expected_generation integer,
    expected_lease_token uuid, expected_owner text
) RETURNS TABLE (completed boolean, phase text, disposition text, closure_revision bigint, last_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    request_row public.erasure_request%ROWTYPE;
    verify_digest bytea;
    complete_digest bytea;
BEGIN
    -- Lock order is project exclusive, then exact live request; it excludes a
    -- late binder through every proof and both terminal receipts.
    PERFORM public.tracebed_erasure_lock_project(expected_project_id);
    request_row := public.tracebed_erasure_assert_lease(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
    );
    IF request_row.phase <> 'external_purged'
       OR public.tracebed_erasure_primary_remaining(expected_project_id, expected_request_id) <> 0
       OR (SELECT count(*) FROM public.erasure_store_checkpoint AS checkpoint
            WHERE checkpoint.project_id = expected_project_id
              AND checkpoint.request_id = expected_request_id
              AND checkpoint.store_code = ANY(request_row.store_manifest)
              AND checkpoint.verified_revision = request_row.closure_revision)
            <> cardinality(request_row.store_manifest) THEN
        RAISE EXCEPTION 'erasure verification denied' USING ERRCODE = 'P0014';
    END IF;
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        expected_owner, 'fence_finalize'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        expected_owner, 'request_update'
    );
    PERFORM public.tracebed_erasure_mint_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        expected_owner, 'receipt_insert'
    );
    verify_digest := sha256(convert_to('tracebed.erasure-verify/v1','UTF8')
        || uuid_send(expected_project_id) || uuid_send(expected_request_id)
        || int8send(request_row.closure_revision));
    PERFORM public.tracebed_erasure_append_receipt(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        'verify','succeeded','ok',0,request_row.closure_revision,verify_digest
    );
    UPDATE public.subject_fence
       SET state = 'erased', erased_at = statement_timestamp()
     WHERE project_id = expected_project_id AND request_id = expected_request_id AND state = 'fenced';
    UPDATE public.run_fence
       SET state = 'erased', erased_at = statement_timestamp()
     WHERE project_id = expected_project_id AND request_id = expected_request_id AND state = 'fenced';
    IF request_row.scope = 'project' THEN
        PERFORM public.tracebed_erasure_tombstone_project(
            expected_project_id, expected_request_id, expected_generation, expected_lease_token, expected_owner
        );
    END IF;
    complete_digest := public.tracebed_erasure_append_receipt(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token,
        'complete','succeeded','ok',0,request_row.closure_revision,
        sha256(convert_to('tracebed.erasure-complete/v1','UTF8') || verify_digest)
    );
    -- `verified` is intentionally only visible inside this transaction.  The
    -- deferred constraint trigger rejects any crash path that commits it.
    UPDATE public.erasure_request
       SET phase = 'verified', verified_at = statement_timestamp(), last_code = 'in_progress',
           updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    UPDATE public.erasure_request
       SET phase = 'scope_complete', disposition = 'scope_complete', completed_at = statement_timestamp(),
           final_receipt_digest = complete_digest, lease_token = NULL, lease_owner = NULL,
           lease_expires_at = NULL, retry_not_before = NULL, last_code = 'scope_complete',
           updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
     WHERE project_id = expected_project_id AND request_id = expected_request_id;
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'receipt_insert'
    );
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'request_update'
    );
    PERFORM public.tracebed_erasure_drop_capability(
        expected_project_id, expected_request_id, expected_generation, expected_lease_token, 'fence_finalize'
    );
    RETURN QUERY SELECT true, 'scope_complete'::text, 'scope_complete'::text,
                        request_row.closure_revision, 'scope_complete'::text;
END;
$$;

-- E3 is EXECUTE-only.  No erasure login or membership is provisioned by this
-- source artifact; deployment activation remains a later HBA/login gate.
REVOKE ALL ON public.erasure_external_work, public.erasure_store_checkpoint,
              public.erasure_execution_capability
    FROM PUBLIC, tracebed_app, tracebed_api, tracebed_worker,
         tracebed_api_group, tracebed_worker_group, tracebed_erasure_group;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM tracebed_erasure_group;
REVOKE ALL ON FUNCTION public.tracebed_erasure_manifest_is_valid(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_frame(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_closure_digest(uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_manifest_digest(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_assert_caller() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_assert_lease(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_capable(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mint_capability(uuid,uuid,integer,uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_drop_capability(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_lock_project(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_drop_project_partitions(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_tombstone_project(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_receipt_digest(uuid,uuid,bigint,integer,text,text,text,integer,bigint,bigint,bytea,bytea,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_append_receipt(uuid,uuid,integer,uuid,text,text,text,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_selected(uuid,text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mint_request_capability(uuid,uuid,integer,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_trace_manifest_digest_for_request(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_primary_remaining(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_next(text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_claim_request(uuid,text,integer,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_renew(uuid,uuid,integer,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_crypto_step(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_trace_refs_batch(uuid,uuid,integer,uuid,text,bigint,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_seal_trace_manifest(uuid,uuid,integer,uuid,text,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_prepare_primary(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_external_work_batch(uuid,uuid,integer,uuid,text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_mark_external_work(uuid,uuid,integer,uuid,text,uuid,bigint,bigint,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_close_external_step(uuid,uuid,integer,uuid,text,text,bigint,bigint,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_verify_and_complete(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_fail(uuid,uuid,integer,uuid,text,text,text,text,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_release(uuid,uuid,integer,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_resume_blocked(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_inspect(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tracebed_erasure_request_status_by_actor(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_claim_next(text,integer,text[]),
    public.tracebed_erasure_claim_request(uuid,text,integer,text[]),
    public.tracebed_erasure_renew(uuid,uuid,integer,uuid,text,integer),
    public.tracebed_erasure_crypto_step(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_trace_refs_batch(uuid,uuid,integer,uuid,text,bigint,uuid,text,integer),
    public.tracebed_erasure_seal_trace_manifest(uuid,uuid,integer,uuid,text,bigint,bigint,bytea),
    public.tracebed_erasure_prepare_primary(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_primary_batch(uuid,uuid,integer,uuid,text,integer),
    public.tracebed_erasure_external_work_batch(uuid,uuid,integer,uuid,text,text,integer),
    public.tracebed_erasure_mark_external_work(uuid,uuid,integer,uuid,text,uuid,bigint,bigint,bytea,text),
    public.tracebed_erasure_close_external_step(uuid,uuid,integer,uuid,text,text,bigint,bigint,bytea,text),
    public.tracebed_erasure_verify_and_complete(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_fail(uuid,uuid,integer,uuid,text,text,text,text,bigint,bytea),
    public.tracebed_erasure_release(uuid,uuid,integer,uuid,text),
    public.tracebed_erasure_resume_blocked(uuid,text), public.tracebed_erasure_inspect(uuid)
TO tracebed_erasure_group;
GRANT EXECUTE ON FUNCTION public.tracebed_erasure_request_status_by_actor(uuid,uuid)
TO tracebed_api_group;

REVOKE ALL ON FUNCTION public.tracebed_erasure_refresh_late_closure(uuid,uuid,uuid[],uuid[]) FROM PUBLIC;

-- The c12 epoch is deliberately the final state-changing statement.  The
-- checked-in profile fixture is regenerated from this complete E3 source.
INSERT INTO public.authority_acl_epoch (
    epoch, profile, profile_version, source_acl_digest, result_acl_digest,
    source_schema_digest, result_schema_digest, yoyo_lock_repair
) SELECT
    (SELECT max(epoch) + 1 FROM public.authority_acl_epoch),
    'cutover_0012'::public.authority_acl_profile, 2,
    (SELECT result_acl_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
    public.authority_acl_security_assert('cutover_0012'::public.authority_acl_profile),
    (SELECT result_schema_digest FROM public.authority_acl_epoch ORDER BY epoch DESC LIMIT 1),
    public.authority_schema_security_assert('cutover_0012'::public.authority_acl_profile),
    'not_required'::public.authority_yoyo_lock_repair;
