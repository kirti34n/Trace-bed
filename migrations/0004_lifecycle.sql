-- depends: 0003_rls

-- 0004_lifecycle.sql — status-writer chunk (docs/FIDELITY-AUDIT.md §1/§5/§11 finding M1;
-- PLAN.md §5, §11).
--
-- The audit's own words: "There is no `UPDATE memory_item` statement anywhere in `src/`
-- ... promotion, staleness, two-strike retirement, archiving, pinning and crypto-shred
-- tombstoning are all COMPUTED CORRECTLY and NONE can be saved." This migration adds the
-- two things `stores.pg.lifecycle.LifecycleWriter` needs to persist a transition
-- `domain.state_machine.apply()` already approved:
--
--   1. `memory_status_log` — the transition log the dashboard MemoryDetail view
--      renders an empty panel for today (PLAN.md §11 M1's audit trail half). Partitioned,
--      FORCE RLS, `project_id` in the PK, exactly like every other learning-plane table
--      (PLAN.md §5) — D-105 already logged this migration set's RLS policy form
--      (`NULLIF(current_setting(...), '')::uuid`, deny-on-unset, fail-closed); this table's
--      policy is the same predicate, not a new decision.
--   2. `memory_item.epoch_id` — PLAN.md §5's `scoring_epoch` table is created, partitioned
--      and RLS-protected in 0001/0003 and, per the audit, written and read by nothing,
--      because NO partitioned table carries an epoch to compare against. Invariant: "cross-
--      epoch Q comparison is rejected" (`domain.errors.CrossEpochComparison`) is
--      unenforceable while the epoch a row was scored under is not on the row itself. This
--      migration adds the column only; a writer for it belongs to whichever chunk owns
--      `ScorerRepoPort`'s Postgres implementation (PLAN.md §11 M3), not this one — status
--      writes and Q/epoch writes are different transitions on different columns.
--
-- No FOREIGN KEY from `memory_status_log` back to `memory_item`, matching every other
-- table in 0002_partitioned.sql: a partitioned child's FK target must be identically
-- indexed on every partition, and this repository's project-deletion path is
-- `stores.pg.partitions.drop_project` (DETACH+DROP), not `ON DELETE CASCADE` — an FK here
-- would only add planner/lock overhead across that path for no isolation benefit (see
-- 0002_partitioned.sql's own header for the identical reasoning applied to the first 13
-- tables).
--
-- CONTRACT GAP (reported, not silently worked around): this migration creates the empty
-- partitioned PARENT only, per 0002_partitioned.sql's own convention ("Per-project
-- partitions of these tables ... are created by stores.pg.partitions
-- .create_project_partitions using the templates in stores.pg.ddl -- NOT by this
-- migration"). `stores/pg/ddl.py` (`PARTITIONED_TABLES`, its index/RLS/grant templates)
-- and `stores/pg/partitions.py` (`create_project_partitions`, `drop_project`,
-- `ensure_schema_current`) are NOT in this chunk's file list. Until whoever owns those adds
-- `memory_status_log` to `PARTITIONED_TABLES` and gives it at least one per-partition
-- index (`(project_id, memory_id, changed_at)` is what the dashboard's MemoryDetail
-- transition-log panel and any per-memory history query need), no project has a partition
-- of this table and every `LifecycleWriter` history INSERT fails against a real Postgres
-- with "no partition of relation found for row" — the status UPDATE itself does not depend
-- on this and is unaffected. `tests/phase3/test_status_persistence.py` documents this gap
-- at its integration-marked test.
--
-- Also NOT in this chunk's file list: `tests/phase0/test_migrations.py`'s hardcoded
-- `MIGRATION_IDS = ("0001_registries", "0002_partitioned", "0003_rls")` (read by
-- `test_yoyo_can_read_every_migration_and_resolve_dependencies`, which calls
-- `stores.pg.migrate.read_all_migrations()` — a directory scan that now returns four ids).
-- That tuple needs `"0004_lifecycle"` appended; the one-line fix belongs to whoever owns
-- that test file, and this migration cannot land without that test going red until it is
-- made. Every other migration test in that file reads one named `.sql` file rather than
-- scanning the directory and is unaffected (verified by inspection, not by editing a file
-- outside this chunk's ownership).

ALTER TABLE memory_item ADD COLUMN epoch_id integer;

-- memory_status_log: one row per persisted `apply()` result. `reason`/`evidence`/
-- `epoch_id` are nullable/defaulted because `workers.edit_ops.MemoryStatusWrite` — the
-- shape `LifecycleWriter.persist_status` actually receives from its three existing callers
-- (`workers/edit_ops.py:203`, `workers/forensics.py:140`, `workers/preferences.py`) — carries
-- neither a reason string nor an evidence snapshot nor a scoring epoch; only `memory_id`,
-- `from_status`, `to_status`, `now`, and an optional `actor_principal`. Widening those three
-- Protocols is outside this chunk's file list (owned by chunks `phase3-edit-ops` and
-- `phase3-forensics`); `LifecycleWriter.persist_status` accepts them as optional keyword
-- arguments so a future richer caller can populate them without a schema change.
CREATE TABLE memory_status_log (
    history_id   uuid NOT NULL DEFAULT gen_random_uuid(),
    project_id   uuid NOT NULL,
    memory_id    uuid NOT NULL,
    from_status  text NOT NULL
                     CHECK (from_status IN (
                         'quarantined', 'candidate', 'validated', 'superseded',
                         'stale', 'retired', 'archived', 'pinned', 'tombstoned'
                     )),
    to_status    text NOT NULL
                     CHECK (to_status IN (
                         'quarantined', 'candidate', 'validated', 'superseded',
                         'stale', 'retired', 'archived', 'pinned', 'tombstoned'
                     )),
    reason       text NOT NULL DEFAULT '',
    actor        uuid,
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    epoch_id     integer,
    changed_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, history_id),
    CHECK (from_status <> to_status)
) PARTITION BY LIST (project_id);

-- RLS: same predicate as every other learning-plane table (0003_rls.sql's header comment
-- carries the full rationale for the NULLIF/fail-closed form; not repeated here). Applied
-- inline rather than in a follow-up migration because 0003 already ran and this table did
-- not exist when it did.
ALTER TABLE memory_status_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_status_log FORCE ROW LEVEL SECURITY;

CREATE POLICY memory_status_log_isolation ON memory_status_log
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);

-- No explicit GRANT statement: 0003_rls.sql's `ALTER DEFAULT PRIVILEGES IN SCHEMA public`
-- already covers every table the migration role creates in this schema from here on
-- (0003's own comment on that block), so `tracebed_app` gets SELECT/INSERT/UPDATE/DELETE on
-- this table the moment it is created, exactly as it did for nothing extra when 0002's 13
-- tables were made 0003's grantees.
