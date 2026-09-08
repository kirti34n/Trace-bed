-- depends: 0008_trace_learning_job

-- A terminal trace archive is an immutable learning input.  The repository's
-- UPSERT predicate is a useful first line, but it cannot constrain a caller
-- that reaches the table directly.  This parent trigger is cloned onto every
-- existing and future partition by PostgreSQL, so it protects all write paths
-- while leaving non-terminal gap repair and owner-driven partition DROP intact.
CREATE FUNCTION trace_index_enforce_terminal_immutability() RETURNS trigger
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

CREATE TRIGGER trace_index_terminal_immutability_guard
    BEFORE UPDATE OR DELETE ON trace_index
    FOR EACH ROW EXECUTE FUNCTION trace_index_enforce_terminal_immutability();

-- 0003's default privileges granted DELETE to every partition.  Repair the
-- parent and every already-created trace_index child now; ddl.py performs the
-- same revoke after creating each future child.  Erasure remains an owner-only
-- partition DROP rather than application row DELETE.
REVOKE DELETE ON trace_index FROM tracebed_app;
GRANT SELECT, INSERT, UPDATE ON trace_index TO tracebed_app;

DO $$
DECLARE
    child regclass;
BEGIN
    FOR child IN
        SELECT inhrelid::regclass
        FROM pg_inherits
        WHERE inhparent = 'trace_index'::regclass
    LOOP
        EXECUTE format('REVOKE DELETE ON TABLE %s FROM tracebed_app', child);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %s TO tracebed_app', child);
    END LOOP;
END;
$$;
