-- 0002_partitioned.rollback.sql — the rollback half of 0002_partitioned.sql.
-- See 0003_rls.rollback.sql's header for why these companion files exist.
--
-- CASCADE is deliberate and bounded: the only dependents of these parents are
-- their own per-project partitions (created by stores/pg/partitions.py, which
-- yoyo has never seen and cannot enumerate) plus those partitions' indexes
-- and policies. Dropping the parent is exactly how the partition lifecycle is
-- meant to end. Nothing outside 0002 depends on these tables — 0002 declares
-- no foreign key into the 0001 registries, by design.

DROP TABLE IF EXISTS
    dead_letter,
    work_queue,
    review_queue,
    spend_ledger,
    invalidation_event,
    blackboard_entry,
    retrieval_event,
    injection_log,
    outcome_event,
    subject_key,
    trace_subject,
    trace_index,
    derived_state,
    memory_link,
    memory_item
CASCADE;
