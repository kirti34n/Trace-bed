DROP TRIGGER IF EXISTS trace_index_terminal_immutability_guard ON trace_index;
DROP FUNCTION IF EXISTS trace_index_enforce_terminal_immutability();

-- Restore 0003's generic DML grant when rolling this migration back.
GRANT DELETE ON trace_index TO tracebed_app;

DO $$
DECLARE
    child regclass;
BEGIN
    FOR child IN
        SELECT inhrelid::regclass
        FROM pg_inherits
        WHERE inhparent = 'trace_index'::regclass
    LOOP
        EXECUTE format('GRANT DELETE ON TABLE %s TO tracebed_app', child);
    END LOOP;
END;
$$;
