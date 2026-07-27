-- 0001_registries.rollback.sql — the rollback half of 0001_registries.sql.
-- See 0003_rls.rollback.sql's header for why these companion files exist.
--
-- The `vector` and `pg_textsearch` EXTENSIONS are deliberately NOT dropped.
-- 0001 creates them with `IF NOT EXISTS`, so it does not know whether it
-- created them or found them already installed (the compose image ships
-- both); dropping an extension this migration may not have created would
-- destroy state belonging to something else in the same database. Re-apply
-- is unaffected — `CREATE EXTENSION IF NOT EXISTS` is idempotent. Everything
-- 0001 unambiguously created is removed below.
--
-- CASCADE covers the FK web among these nine tables (agent_registration and
-- the two config tables reference project/agent_type) without pinning a drop
-- order, and reaches killswitch_state_scope_uq.

DROP TABLE IF EXISTS
    killswitch_state,
    agent_type_config,
    project_config,
    scoring_epoch,
    embedding_model,
    agent_registration,
    agent_type,
    principal,
    project
CASCADE;
