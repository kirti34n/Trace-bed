-- 0003_rls.rollback.sql — the rollback half of 0003_rls.sql.
--
-- These `.rollback.sql` companions are not optional. yoyo pairs each forward
-- statement with a rollback statement from this file; where the file is
-- ABSENT, `MigrationStep.rollback` returns immediately (yoyo/migrations.py:
-- "if self._rollback is None: return") and yoyo still un-marks the migration
-- as applied. Without this file, `rollback_migrations(dsn, all=True)` would
-- report a clean rollback while every table, policy, and grant survived —
-- and the next `apply_migrations()` would die on `relation "project" already
-- exists`. PHASE-0 Task 5's proving test ("yoyo apply then yoyo rollback
-- clean") is unpassable without these three files.
--
-- yoyo reverses this file's statement list before pairing it with the
-- forward statements and then walks the steps backwards, so the net effect
-- is that the statements below execute top to bottom.
--
-- What is NOT undone: the `tracebed_app` ROLE itself. Deployment owns that
-- role's existence and its credential (docker/initdb/01-roles.sql creates it
-- before any migration runs); this migration only ever owned its grants, so
-- rolling back returns it to a privilege-free role rather than deleting
-- something the deployment provisioned.

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM tracebed_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT ON SEQUENCES FROM tracebed_app;

REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM tracebed_app;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM tracebed_app;

REVOKE USAGE ON SCHEMA public FROM tracebed_app;

-- One block over the 13 partitioned parents: drop the isolation policy, then
-- turn RLS off. Looping keeps this file's statement count at or below the
-- forward migration's, which yoyo requires (a rollback statement with no
-- forward partner would be paired with `apply=None` and crash on re-apply).
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'memory_item', 'memory_link', 'derived_state', 'trace_index',
        'trace_subject', 'subject_key', 'outcome_event', 'injection_log',
        'retrieval_event', 'blackboard_entry', 'invalidation_event',
        'spend_ledger', 'review_queue'
    ]
    LOOP
        IF to_regclass('public.' || t) IS NOT NULL THEN
            EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_isolation', t);
            EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', t);
            EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', t);
        END IF;
    END LOOP;
END
$$;
