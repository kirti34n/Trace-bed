-- depends: 0002_partitioned

-- 0003_rls.sql — PHASE-0 Task 6, RLS half (docs/PHASE0-CONTRACT.md §1, C-09;
-- PLAN.md §5 invariant 4).
--
-- RLS is the *backstop*, not the primary control — the typed repository
-- (every builder requires a ProjectId, scripts/raw_sql_lint.py bans raw SQL
-- outside stores/pg/) is primary. This migration exists so that a bug which
-- forgets to set the session GUC, or a caller who reaches Postgres directly,
-- gets zero rows instead of another project's data.
--
-- The predicate is
--   project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid
-- and every character of that is load-bearing. PLAN.md §5 and
-- docs/PHASE0-CONTRACT.md §14 both spell it `current_setting('tracebed.project_id')::uuid`;
-- that literal form CANNOT satisfy the requirement both documents also
-- state — PHASE-0 Task 6 ("direct SQL as app role without the GUC set
-- returns zero rows from every partitioned table") and PLAN.md §2 invariant
-- 4 probe (g) ("repo bypass attempt with RLS GUC unset → zero rows"). This
-- deviation needs a DECISIONS.md entry at merge; it is reported, not
-- silent. Why each piece:
--
--   * `, true` is `missing_ok`. Without it, an unset GUC raises
--     undefined_object instead of returning zero rows — an error a caller
--     can catch and route around, and a test the gate cannot pass. Worse,
--     the strict form's behaviour is session-history-dependent: once ANY
--     transaction in a session has called set_config on the name, the
--     parameter exists for the rest of that session and stops raising.
--   * `NULLIF(..., '')` because the GUC is very often present-but-empty
--     rather than absent: docker/initdb/01-roles.sql runs
--     `ALTER DATABASE tracebed SET tracebed.project_id TO ''`, so every
--     session starts with the empty string, and `''::uuid` raises
--     invalid_text_representation on every row of every query. NULLIF turns
--     that back into SQL NULL, and `project_id = NULL` is never true
--     (three-valued logic) — zero rows, no error, fail-closed.
--   * A GUC holding garbage still raises rather than matching. That is
--     also fail-closed: an error is never a leak.
--
-- The GUC is set exactly once per transaction, as its first statement, by
-- Repo.tx / every partitioned-table Repo method:
--   SELECT set_config('tracebed.project_id', %(project_id)s, true);
-- ('true' = local to the transaction; SET LOCAL cannot bind a parameter,
-- which is why set_config() is used instead of a literal SET LOCAL string.)
-- stores/pg/ddl.py repeats this exact predicate on every per-project
-- partition; the two must never diverge (test_partitions.py asserts it).
--
-- Applied to all 13 LIST-partitioned tables from 0002_partitioned.sql. Not
-- applied to work_queue/dead_letter (unpartitioned, contract §5.3) or to the
-- 0001 registries (unpartitioned, small, admin-write; scope derivation
-- itself reads agent_registration before any GUC exists to check).

ALTER TABLE memory_item        ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_link        ENABLE ROW LEVEL SECURITY;
ALTER TABLE derived_state      ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_index        ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_subject      ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject_key        ENABLE ROW LEVEL SECURITY;
ALTER TABLE outcome_event      ENABLE ROW LEVEL SECURITY;
ALTER TABLE injection_log      ENABLE ROW LEVEL SECURITY;
ALTER TABLE retrieval_event    ENABLE ROW LEVEL SECURITY;
ALTER TABLE blackboard_entry   ENABLE ROW LEVEL SECURITY;
ALTER TABLE invalidation_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_ledger       ENABLE ROW LEVEL SECURITY;
ALTER TABLE review_queue       ENABLE ROW LEVEL SECURITY;

-- FORCE makes RLS apply even to the table owner (who would otherwise bypass
-- it by default — PostgreSQL's normal behaviour). It does NOT make RLS
-- apply to superusers or roles with BYPASSRLS; that is why `tracebed_app`
-- below is created deliberately without either (contract §14: "app role is
-- not owner, no BYPASSRLS").
ALTER TABLE memory_item        FORCE ROW LEVEL SECURITY;
ALTER TABLE memory_link        FORCE ROW LEVEL SECURITY;
ALTER TABLE derived_state      FORCE ROW LEVEL SECURITY;
ALTER TABLE trace_index        FORCE ROW LEVEL SECURITY;
ALTER TABLE trace_subject      FORCE ROW LEVEL SECURITY;
ALTER TABLE subject_key        FORCE ROW LEVEL SECURITY;
ALTER TABLE outcome_event      FORCE ROW LEVEL SECURITY;
ALTER TABLE injection_log      FORCE ROW LEVEL SECURITY;
ALTER TABLE retrieval_event    FORCE ROW LEVEL SECURITY;
ALTER TABLE blackboard_entry   FORCE ROW LEVEL SECURITY;
ALTER TABLE invalidation_event FORCE ROW LEVEL SECURITY;
ALTER TABLE spend_ledger       FORCE ROW LEVEL SECURITY;
ALTER TABLE review_queue       FORCE ROW LEVEL SECURITY;

CREATE POLICY memory_item_isolation ON memory_item
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY memory_link_isolation ON memory_link
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY derived_state_isolation ON derived_state
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY trace_index_isolation ON trace_index
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY trace_subject_isolation ON trace_subject
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY subject_key_isolation ON subject_key
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY outcome_event_isolation ON outcome_event
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY injection_log_isolation ON injection_log
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY retrieval_event_isolation ON retrieval_event
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY blackboard_entry_isolation ON blackboard_entry
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY invalidation_event_isolation ON invalidation_event
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY spend_ledger_isolation ON spend_ledger
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
CREATE POLICY review_queue_isolation ON review_queue
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);

-- The application role. Deliberately NOT the table owner (the migration
-- runner / admin role that executed 0001-0002 owns every table) and
-- deliberately NOT granted BYPASSRLS — either one would silently disable
-- every policy above for this role regardless of FORCE.
--
-- NO PASSWORD AND NO LOGIN ARE SET HERE, on purpose. Deployment owns the
-- credential: docker/initdb/01-roles.sql creates this role with LOGIN and a
-- dev password before any migration runs, and production provisioning does
-- the equivalent with a real secret. A password in a migration would be a
-- second source of truth for a credential (the two already disagreed:
-- initdb's was `tracebed_app_dev`, this file's was not) and a checked-in
-- secret besides. This block only guarantees the role EXISTS so the grants
-- below have a grantee — an unprivileged, unusable role until a deployment
-- gives it LOGIN.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tracebed_app') THEN
        CREATE ROLE tracebed_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                                 NOBYPASSRLS NOREPLICATION;
    END IF;
END
$$;

-- Enforce the security-relevant attributes, and enforce them CONDITIONALLY.
-- Unconditional `ALTER ROLE ... NOBYPASSRLS` requires superuser, which would
-- make this migration unrunnable on any deployment whose migration role is
-- merely a table owner with CREATEROLE — the common hardened setup. When the
-- role is already provisioned correctly (compose, CI, and the block above
-- all do), nothing is altered and no superuser is needed. When it is NOT
-- correct, the ALTER runs and either fixes it or fails loudly: a role with
-- BYPASSRLS silently voids every policy above, so proceeding quietly is the
-- one outcome that must not be possible.
DO $$
DECLARE
    r record;
BEGIN
    SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication
      INTO r FROM pg_roles WHERE rolname = 'tracebed_app';
    IF r.rolsuper OR r.rolbypassrls OR r.rolcreatedb
       OR r.rolcreaterole OR r.rolreplication THEN
        ALTER ROLE tracebed_app NOSUPERUSER NOCREATEDB NOCREATEROLE
                                NOBYPASSRLS NOREPLICATION;
    END IF;
END
$$;

-- DML only — no DDL, no ownership, no TRUNCATE (TRUNCATE has no row-level
-- filter to apply RLS to, so it is deliberately withheld).
GRANT USAGE ON SCHEMA public TO tracebed_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tracebed_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tracebed_app;

-- ...but NOT on yoyo's own bookkeeping. `ON ALL TABLES IN SCHEMA public`
-- sweeps up `_yoyo_migration` / `_yoyo_log` / `_yoyo_version` / `_yoyo_lock`,
-- which yoyo created before 0001 ran. The application never reads or writes
-- migration history; letting the role it connects as DELETE from
-- `_yoyo_migration` would let any SQL-execution bug rewrite the record of
-- which security migrations have been applied — including this one.
DO $$
DECLARE
    t record;
BEGIN
    FOR t IN
        SELECT tablename FROM pg_tables
         WHERE schemaname = 'public' AND tablename LIKE '\_yoyo%'
    LOOP
        EXECUTE format('REVOKE ALL PRIVILEGES ON public.%I FROM tracebed_app', t.tablename);
    END LOOP;
END
$$;

-- Applies only to objects the role executing this migration creates in this
-- schema afterward — per-project partitions created later by
-- stores.pg.partitions still grant tracebed_app explicitly, themselves
-- (stores/pg/ddl.py's partition_grant_statements), rather than relying on
-- this alone. Kept anyway as defense-in-depth for anything created by the
-- same migration role through some other path.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tracebed_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO tracebed_app;
