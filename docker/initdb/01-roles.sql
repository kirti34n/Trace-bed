-- Role separation is load-bearing for invariant 4 (PLAN.md §5).
--
-- FORCE ROW LEVEL SECURITY does not apply to a table's owner, and a role with BYPASSRLS
-- ignores policies outright. So the application connects as tracebed_app, which owns
-- nothing, holds no BYPASSRLS, and has DML only. Migrations run as tracebed_owner.
--
-- If the app ever runs as the owner, every RLS policy in 0003_rls.sql silently stops
-- applying and the leak suite is the only thing left standing between projects.

CREATE ROLE tracebed_app LOGIN PASSWORD 'tracebed_app_dev' NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE tracebed TO tracebed_app;
GRANT USAGE ON SCHEMA public TO tracebed_app;

-- DML only. No DDL: partition creation goes through the owner-run partition manager.
ALTER DEFAULT PRIVILEGES FOR ROLE tracebed_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tracebed_app;
ALTER DEFAULT PRIVILEGES FOR ROLE tracebed_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO tracebed_app;

-- The RLS GUC the repository sets per transaction. Declaring it here means an unset GUC
-- reads as NULL rather than raising, which is what lets the policy fail closed to zero
-- rows instead of raising an error a caller could catch and route around.
ALTER DATABASE tracebed SET tracebed.project_id TO '';
