-- 0004_lifecycle.rollback.sql — the rollback half of 0004_lifecycle.sql.
--
-- See 0003_rls.rollback.sql's header for why these companion files are not optional: yoyo
-- pairs each forward statement with a rollback statement positionally (`zip_longest`), so a
-- rollback with MORE statements than its migration produces a step whose `apply` is `None`
-- and crashes the next `apply_migrations()` call. 0004_lifecycle.sql has 5 statements; this
-- file has 2, well under the ceiling `tests/phase0/test_lifecycle_migration.py` checks for.
--
-- `DROP TABLE ... CASCADE` on the partitioned parent takes its RLS policy and (were any to
-- exist — none do; see 0004_lifecycle.sql's CONTRACT GAP note) any per-project partitions
-- with it, the same one-statement-undoes-enable+force+policy shape 0002's rollback uses for
-- its 13 tables.

DROP TABLE IF EXISTS memory_status_log CASCADE;

ALTER TABLE memory_item DROP COLUMN IF EXISTS epoch_id;
