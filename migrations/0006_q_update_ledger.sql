-- depends: 0005_bm25

-- 0006_q_update_ledger.sql — the Q-update ledger for ScorerRepoPort's Postgres
-- implementation (docs/FIDELITY-AUDIT.md M3; PLAN.md §11 M3; workers/scorer.py's
-- module docstring, first contract gap).
--
-- The scorer (invariant 8) needs three things migrations 0001-0005 cannot answer,
-- because memory_item stores only a memory's CURRENT values (one q_value, one
-- scored_use_count, one last_scored_at) and NOTHING records the individual Q
-- updates that produced them (reports.py:15-27, verbatim: "Q-value trajectory has
-- no history table ... QUpdate.epoch_id is carried only in-memory, never durably"):
--
--   1. `ScorerRepoPort.applied_event_ids` — the replay-idempotency ledger: every
--      event_id that has EVER moved this memory's Q, so a redelivered outcome
--      event never moves Q twice (NOT day-scoped).
--   2. `ScorerRepoPort.scored_updates_today` — how many Q updates a memory received
--      on a given UTC calendar day, the one-update-per-memory-per-day cap counter.
--   3. The durable trail retirement reads: DISTINCT PRINCIPALS OVER SCORED UPDATES
--      (D-021, PLAN.md §5's "Q < 0.25 after >=4 scored uses from >=K distinct
--      principals" — the qualifier attaches to SCORED uses, which only this table
--      records; outcome_event also holds the implicit/cap-skipped events that never
--      moved Q). `epoch_id` satisfies invariant 7 ("every Q update records
--      scoring_epoch"); `previous_q`/`contribution` make each step auditable.
--
-- Partitioned by project_id with project_id in the PK, FORCE RLS, exactly like every
-- other learning-plane table (PLAN.md §5). The RLS policy is 0003/0004's exact
-- deny-on-unset form (`NULLIF(current_setting('tracebed.project_id', true), '')::uuid`)
-- — not a new decision, the same predicate; see 0003_rls.sql's header for the full
-- rationale on why every character of it is load-bearing.
--
-- PK is (project_id, memory_id, event_id), NOT (project_id, event_id): one
-- outcome_event.event_id can touch several injected memories (one ScoringEvent each),
-- so replay-idempotency is per (memory_id, event_id). `ON CONFLICT (project_id,
-- memory_id, event_id) DO NOTHING` on that PK is the atomic replay guard the store's
-- apply_q_update composes.
--
-- No FOREIGN KEY back to memory_item, matching every other table in
-- 0002_partitioned.sql (a partitioned child's FK target must be identically indexed on
-- every partition; project deletion is DETACH+DROP via stores.pg.partitions.drop_project,
-- not ON DELETE CASCADE) — see 0002's header for the identical reasoning.
--
-- CONTRACT GAP (reported, not silently worked around): this migration creates the empty
-- partitioned PARENT only, per 0002/0004's convention. `stores/pg/ddl.py`
-- (`PARTITIONED_TABLES`, its per-partition RLS/grant/index templates) and
-- `stores/pg/partitions.py` are NOT in this chunk's file list. Until the integration pass
-- adds `memory_q_update` to `PARTITIONED_TABLES` (with a per-partition index on
-- `(project_id, memory_id, scored_at)` so scored_updates_today is an index scan), no
-- project has a partition of this table and every ledger INSERT fails against a real
-- Postgres with "no partition of relation found for row". The store's own test provisions
-- the partition directly to exercise the round trip; see tests/phase3/test_pg_scoring.py.
--
-- No explicit GRANT: 0003_rls.sql's `ALTER DEFAULT PRIVILEGES IN SCHEMA public` already
-- grants tracebed_app SELECT/INSERT/UPDATE/DELETE on every table the migration role creates
-- from here on, exactly as it did for 0004's memory_status_log.

CREATE TABLE memory_q_update (
    project_id    uuid NOT NULL,
    memory_id     uuid NOT NULL,
    event_id      uuid NOT NULL,
    principal_id  uuid NOT NULL,
    previous_q    double precision NOT NULL,
    new_q         double precision NOT NULL,
    contribution  double precision NOT NULL,
    epoch_id      integer NOT NULL,
    scored_at     timestamptz NOT NULL,
    PRIMARY KEY (project_id, memory_id, event_id)
) PARTITION BY LIST (project_id);

ALTER TABLE memory_q_update ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_q_update FORCE ROW LEVEL SECURITY;

CREATE POLICY memory_q_update_isolation ON memory_q_update
    USING (project_id = NULLIF(current_setting('tracebed.project_id', true), '')::uuid);
