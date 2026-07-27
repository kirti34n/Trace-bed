-- 0006_q_update_ledger.rollback.sql — the rollback half of 0006_q_update_ledger.sql.
--
-- See 0003_rls.rollback.sql / 0004_lifecycle.rollback.sql for why these companion files are
-- not optional: yoyo pairs each forward statement with a rollback statement positionally
-- (`zip_longest`), so a rollback with MORE statements than its migration produces a step whose
-- `apply` is `None` and crashes the next `apply_migrations()` call. 0006_q_update_ledger.sql
-- has 4 statements; this file has 1, well under that ceiling.
--
-- `DROP TABLE ... CASCADE` on the partitioned parent takes its RLS policy and any per-project
-- partitions with it — the same one-statement-undoes-create+enable+force+policy shape 0004's
-- rollback uses for memory_status_log.

DROP TABLE IF EXISTS memory_q_update CASCADE;
