-- depends: 0007_project_provisioning

-- Durable, project-scoped lease substrate for trace learning.  There is no
-- foreign key deliberately: project removal is partition DETACH+DROP and a
-- trace archive can outlive a registry row during controlled recovery.
CREATE TABLE trace_learning_job (
    project_id          uuid NOT NULL,
    run_id              uuid NOT NULL,
    pipeline            text NOT NULL,
    pipeline_version    integer NOT NULL,
    state               text NOT NULL DEFAULT 'pending',
    attempts            integer NOT NULL DEFAULT 0,
    max_attempts        integer NOT NULL DEFAULT 3,
    available_at        timestamptz NOT NULL DEFAULT now(),
    lease_token         uuid,
    lease_owner         text,
    lease_expires_at    timestamptz,
    trace_ended_at      timestamptz NOT NULL,
    schedule_source     text NOT NULL DEFAULT 'live',
    trace_digest        bytea,
    result_digest       bytea,
    memory_ids          uuid[] NOT NULL DEFAULT '{}'::uuid[],
    skip_code           text,
    last_error_code     text,
    scheduled_at        timestamptz NOT NULL DEFAULT now(),
    first_started_at    timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    PRIMARY KEY (project_id, run_id, pipeline, pipeline_version),
    CONSTRAINT trace_learning_job_pipeline_safe
        CHECK (pipeline ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT trace_learning_job_pipeline_version_positive
        CHECK (pipeline_version >= 1),
    CONSTRAINT trace_learning_job_state_known
        CHECK (state IN ('pending', 'running', 'retry', 'succeeded', 'skipped', 'dead')),
    CONSTRAINT trace_learning_job_attempts_bounded
        CHECK (max_attempts BETWEEN 1 AND 32 AND attempts BETWEEN 0 AND max_attempts),
    CONSTRAINT trace_learning_job_state_attempts_consistent
        CHECK (
            (state = 'pending' AND attempts = 0)
            OR (state = 'retry' AND attempts >= 1 AND attempts < max_attempts)
            OR (state IN ('running', 'succeeded', 'skipped', 'dead') AND attempts >= 1)
        ),
    CONSTRAINT trace_learning_job_schedule_source_known
        CHECK (schedule_source IN ('live', 'backfill')),
    CONSTRAINT trace_learning_job_digest_lengths
        CHECK (
            (trace_digest IS NULL OR octet_length(trace_digest) = 32)
            AND (result_digest IS NULL OR octet_length(result_digest) = 32)
        ),
    CONSTRAINT trace_learning_job_owner_and_codes_safe
        CHECK (
            (lease_owner IS NULL OR lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$')
            AND (skip_code IS NULL OR skip_code ~ '^[a-z][a-z0-9_]{0,63}$')
            AND (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$')
        ),
    CONSTRAINT trace_learning_job_skip_code_iff_skipped
        CHECK (
            (state = 'skipped' AND skip_code IS NOT NULL)
            OR (state <> 'skipped' AND skip_code IS NULL)
        ),
    CONSTRAINT trace_learning_job_error_code_iff_retry_or_dead
        CHECK (
            (state IN ('retry', 'dead') AND last_error_code IS NOT NULL)
            OR (state NOT IN ('retry', 'dead') AND last_error_code IS NULL)
        ),
    CONSTRAINT trace_learning_job_lease_iff_running
        CHECK (
            (state = 'running'
             AND lease_token IS NOT NULL
             AND lease_owner IS NOT NULL
             AND lease_expires_at IS NOT NULL)
            OR
            (state <> 'running'
             AND lease_token IS NULL
             AND lease_owner IS NULL
             AND lease_expires_at IS NULL)
        ),
    CONSTRAINT trace_learning_job_first_started_consistent
        CHECK ((attempts = 0) = (first_started_at IS NULL)),
    CONSTRAINT trace_learning_job_memory_ids_no_nulls
        CHECK (array_position(memory_ids, NULL::uuid) IS NULL),
    CONSTRAINT trace_learning_job_nonterminal_receipt_empty
        CHECK (
            state IN ('succeeded', 'skipped', 'dead')
            OR (result_digest IS NULL AND finished_at IS NULL AND cardinality(memory_ids) = 0)
        ),
    CONSTRAINT trace_learning_job_terminal_receipt_complete
        CHECK (
            state NOT IN ('succeeded', 'skipped', 'dead')
            OR (result_digest IS NOT NULL AND octet_length(result_digest) = 32 AND finished_at IS NOT NULL)
        ),
    CONSTRAINT trace_learning_job_trace_required_for_success_or_skip
        CHECK (
            state NOT IN ('succeeded', 'skipped')
            OR (trace_digest IS NOT NULL AND octet_length(trace_digest) = 32)
        ),
    CONSTRAINT trace_learning_job_succeeded_shape
        CHECK (
            state <> 'succeeded' OR (skip_code IS NULL AND last_error_code IS NULL)
        ),
    CONSTRAINT trace_learning_job_skipped_shape
        CHECK (
            state <> 'skipped'
            OR (skip_code IS NOT NULL AND last_error_code IS NULL AND cardinality(memory_ids) = 0)
        ),
    CONSTRAINT trace_learning_job_dead_shape
        CHECK (
            state <> 'dead'
            OR (last_error_code IS NOT NULL AND skip_code IS NULL AND cardinality(memory_ids) = 0)
        )
) PARTITION BY LIST (project_id);

ALTER TABLE trace_learning_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_learning_job FORCE ROW LEVEL SECURITY;

CREATE POLICY trace_learning_job_isolation ON trace_learning_job
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);

-- 0003's default privileges include DELETE. Jobs are an audit ledger, not an
-- app-side erasure surface: only owner-run partition DROP removes a project.
REVOKE DELETE ON trace_learning_job FROM tracebed_app;
GRANT SELECT, INSERT, UPDATE ON trace_learning_job TO tracebed_app;

CREATE FUNCTION trace_learning_job_enforce_transition() RETURNS trigger
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

CREATE TRIGGER trace_learning_job_transition_guard
    BEFORE INSERT OR UPDATE OR DELETE ON trace_learning_job
    FOR EACH ROW EXECUTE FUNCTION trace_learning_job_enforce_transition();
