-- depends: 0001_registries

-- 0002_partitioned.sql — PHASE-0 Task 6 (docs/PHASE0-CONTRACT.md §1, §5.5; PLAN.md §5).
--
-- Every learning-plane table: LIST-partitioned by project_id, project_id in
-- every primary key (invariant 4's schema-level backstop — RLS in
-- 0003_rls.sql is the runtime backstop; LIST partitioning is the *lifecycle*
-- mechanism, DECISIONS D-017: project deletion is DETACH+DROP across these
-- 13 tables in one transaction instead of a row-by-row DELETE).
--
-- No table here declares a FOREIGN KEY back to `project`/`agent_type` (the
-- unpartitioned registries from 0001). A partitioned child's FK target must
-- itself be indexed identically on every partition, and project deletion
-- already goes through stores.pg.partitions.drop_project rather than an
-- ON DELETE CASCADE off `project` — an FK here would only add planner/lock
-- overhead across the DETACH+DROP path for no isolation benefit (isolation
-- is project_id-in-PK + RLS, not referential integrity to the registry).
--
-- Per-project partitions of these tables (and their indexes — the HNSW
-- halfvec_cosine_ops ANN index and the pg_textsearch BM25 index on
-- memory_item, btree on hot keys) are created by
-- stores.pg.partitions.create_project_partitions using the templates in
-- stores.pg.ddl — NOT by this migration. A migration only ever creates the
-- empty partitioned parent; there is no project to partition for yet at
-- migration time.

-- memory_item: the vault. scan_verdict_id is NOT NULL with no default —
-- an insert that never went through core.scans is impossible at the schema
-- level (invariant 6/DECISIONS D-024: the scan module precedes every write
-- path). embedding_model_id/version are NOT NULL exactly when embedding is
-- set (mixed rows — no vector yet vs. vector present without its stamp —
-- are both schema errors).
CREATE TABLE memory_item (
    id                       uuid NOT NULL,
    project_id               uuid NOT NULL,
    scope_type               text NOT NULL
                                 CHECK (scope_type IN
                                     ('agent_type', 'workflow_template', 'user', 'project_shared')),
    scope_id                 uuid,
    mem_type                 text NOT NULL
                                 CHECK (mem_type IN ('episodic', 'semantic', 'lesson', 'preference')),
    kind                     text NOT NULL,
    lane                     text NOT NULL CHECK (lane IN ('operational', 'quality')),
    trust_tier               char(1) NOT NULL CHECK (trust_tier IN ('A', 'B')),
    status                   text NOT NULL
                                 CHECK (status IN (
                                     'quarantined', 'candidate', 'validated', 'superseded',
                                     'stale', 'retired', 'archived', 'pinned', 'tombstoned'
                                 )),
    content                  text NOT NULL,
    content_hash             text NOT NULL,
    token_count              integer NOT NULL CHECK (token_count >= 0),
    embedding                halfvec(768),
    embedding_model_id       text,
    embedding_model_version  text,
    lexemes                  tsvector,
    subject_tag              text,
    q_value                  double precision NOT NULL DEFAULT 0.5 CHECK (q_value >= 0 AND q_value <= 1),
    confidence               double precision NOT NULL DEFAULT 0.0,
    scored_use_count         integer NOT NULL DEFAULT 0,
    last_scored_at           timestamptz,
    strike_count             integer NOT NULL DEFAULT 0,
    shadow_confirm_runs      uuid[] NOT NULL DEFAULT '{}',
    cluster_id                uuid,
    ttl_class                 text,
    pinned                    boolean NOT NULL DEFAULT false,
    last_retrieved_at         timestamptz,
    last_revalidated_at       timestamptz,
    status_changed_at         timestamptz,
    valid_from                timestamptz,
    valid_to                  timestamptz,
    created_at                timestamptz NOT NULL DEFAULT now(),
    expired_at                timestamptz,
    provenance                jsonb NOT NULL,
    scan_verdict_id            uuid NOT NULL,
    schema_version             integer NOT NULL DEFAULT 1,
    PRIMARY KEY (project_id, id),
    CHECK (
        (embedding IS NULL AND embedding_model_id IS NULL AND embedding_model_version IS NULL)
        OR (embedding IS NOT NULL AND embedding_model_id IS NOT NULL AND embedding_model_version IS NOT NULL)
    )
) PARTITION BY LIST (project_id);

-- memory_link: supersedes | derived_from | contradicts | related between two
-- memory_item rows in the same project (cross-project links are structurally
-- impossible — src_id/dst_id are looked up through the same-partition
-- memory_item, invariant 4).
CREATE TABLE memory_link (
    project_id  uuid NOT NULL,
    src_id      uuid NOT NULL,
    dst_id      uuid NOT NULL,
    relation    text NOT NULL
                    CHECK (relation IN ('supersedes', 'derived_from', 'contradicts', 'related')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, src_id, dst_id, relation)
) PARTITION BY LIST (project_id);

-- derived_state: OUTSIDE the one state machine (DECISIONS D-014 / SM-05 —
-- deterministic versioned overwrite is a different shape than a governed
-- transition). delta_pct/clamped are the rate-bounded-movement controls
-- from DECISIONS D-022 (±10% clamp per update; a clamp binding 3 consecutive
-- updates raises an alert — that alert logic is a Phase-2 worker, this
-- column is where its input lives).
CREATE TABLE derived_state (
    project_id     uuid NOT NULL,
    agent_type_id  uuid NOT NULL,
    key            text NOT NULL,
    version        integer NOT NULL,
    value          jsonb NOT NULL,
    computed_at    timestamptz NOT NULL DEFAULT now(),
    delta_pct      double precision,
    clamped        boolean NOT NULL DEFAULT false,
    PRIMARY KEY (project_id, agent_type_id, key, version)
) PARTITION BY LIST (project_id);

-- trace_index: completeness + corroboration substrate (DECISIONS D-020).
-- submitter_principal and input_signature_hash are NOT NULL from Phase 0 —
-- without both, "independent" corroboration is uncomputable and the skip
-- degrades to a two-call Sybil bypass (the skip itself still ships disabled
-- until Phase 3, contract §3.9, but the columns it needs exist now so
-- retrofitting never happens). outcome_status defaults to 'pending' and
-- includes 'incomplete' — the sentinel/sequence-gap detection state
-- (ingest.trace_writer.sweep_incomplete, contract §11).
CREATE TABLE trace_index (
    run_id                    uuid NOT NULL,
    project_id                uuid NOT NULL,
    agent_type_id             uuid NOT NULL,
    workflow_template_id      uuid,
    submitter_principal       uuid NOT NULL,
    input_signature_hash      bytea NOT NULL,
    instrumentation_source    text NOT NULL CHECK (instrumentation_source IN ('sdk', 'host_stream')),
    arm                       text NOT NULL DEFAULT 'memory_on' CHECK (arm IN ('memory_on', 'holdout')),
    path                      jsonb,
    started_at                timestamptz,
    ended_at                  timestamptz,
    payload_ref               text,
    outcome_status             text NOT NULL DEFAULT 'pending'
                                   CHECK (outcome_status IN
                                       ('pending', 'ok', 'error', 'cancelled', 'incomplete')),
    PRIMARY KEY (project_id, run_id)
) PARTITION BY LIST (project_id);

-- trace_subject: multi-valued, makes subjects findable for erasure
-- (DECISIONS D-025 — crypto-shredding needs a subject -> run index that did
-- not exist in the original spec's trace_index).
CREATE TABLE trace_subject (
    run_id       uuid NOT NULL,
    project_id   uuid NOT NULL,
    subject_tag  text NOT NULL,
    PRIMARY KEY (project_id, run_id, subject_tag)
) PARTITION BY LIST (project_id);

-- subject_key: crypto-shredding's storage half (crypto.shred.SubjectKeyStore
-- Protocol — crypto/ executes NO SQL itself, contract §14). destroy_subject
-- sets destroyed_at and overwrites wrapped_kek with an empty bytea; it does
-- NOT delete the row (the row's continued existence is what lets a reader
-- distinguish "never had a key" from "erased").
CREATE TABLE subject_key (
    project_id    uuid NOT NULL,
    subject_tag   text NOT NULL,
    key_id        uuid NOT NULL,
    wrapped_kek   bytea NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    destroyed_at  timestamptz,
    PRIMARY KEY (project_id, subject_tag)
) PARTITION BY LIST (project_id);

-- outcome_event: replay-safe by (project_id, event_id) — ON CONFLICT DO
-- NOTHING is the repo's dedup mechanism for a feedback event arriving days
-- after its trace (DECISIONS D-021: principal_id NOT NULL — automatic
-- retirement needs >= K distinct principals, this is where they are
-- counted from). `r` is the outcome polarity in [0,1] the server derives
-- from outcome:"positive"|"negative" — never a caller-supplied weight.
CREATE TABLE outcome_event (
    event_id     uuid NOT NULL,
    run_id       uuid NOT NULL,
    project_id   uuid NOT NULL,
    principal_id uuid NOT NULL,
    adapter      text NOT NULL
                     CHECK (adapter IN ('verdict', 'correction_adapter', 'downstream', 'implicit')),
    r            double precision NOT NULL CHECK (r >= 0 AND r <= 1),
    payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at  timestamptz,
    arrived_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, event_id)
) PARTITION BY LIST (project_id);

-- injection_log: what actually rendered into a prompt, for the kill switch's
-- stratified lift (DECISIONS D-027 — lift is computed on runs where
-- something was injected, so this table is what identifies those runs) and
-- for Recall & Rollback forensics (PLAN.md §8, improvement 1).
CREATE TABLE injection_log (
    run_id       uuid NOT NULL,
    project_id   uuid NOT NULL,
    memory_id    uuid NOT NULL,
    slot         text NOT NULL
                     CHECK (slot IN (
                         'static_prefix', 'fact', 'exemplar',
                         'pitfall', 'candidate_note', 'jit_lesson'
                     )),
    score        double precision NOT NULL,
    tokens       integer NOT NULL CHECK (tokens >= 0),
    injected_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, run_id, memory_id)
) PARTITION BY LIST (project_id);

-- retrieval_event: one row per /v1/retrieve call, every arm and every
-- outcome_code — distinguishes abstention (system working as designed) from
-- timeout (system failing), PLAN.md §5. The Phase 0 stub writes exactly one
-- of these per call with outcome_code='empty_result'.
CREATE TABLE retrieval_event (
    run_id                  uuid NOT NULL,
    project_id              uuid NOT NULL,
    outcome_code            text NOT NULL
                                CHECK (outcome_code IN (
                                    'injected', 'abstained_threshold', 'abstained_rarity',
                                    'empty_result', 'degraded_lexical', 'timeout_prefix_only',
                                    'store_error', 'holdout'
                                )),
    latency_ms              integer NOT NULL CHECK (latency_ms >= 0),
    embed_latency_ms        integer,
    candidates_considered   integer NOT NULL DEFAULT 0,
    top_score               double precision,
    arm                     text NOT NULL CHECK (arm IN ('memory_on', 'holdout')),
    created_at               timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, run_id)
) PARTITION BY LIST (project_id);

-- blackboard_entry: Phase 4 run-state (a named synchronous exception to
-- invariant 5, PLAN.md §7 Phase 4). The table lands in Phase 0 because it is
-- one of the 13 learning-plane partitions every project needs from day one;
-- author_agent is server-derived and the natural key is exactly
-- (project_id, run_id, branch_id, key) — declaring it as the PRIMARY KEY now
-- is what Phase 4's "key-squatting" test (PLAN.md §7) checks against.
--
-- author_agent is `uuid`, not `text`: it is always a PrincipalId (server-derived
-- from the authenticated caller, never caller-asserted), and `stores.pg.blackboard
-- ._row_to_entry` constructs a `PrincipalId` from it. Typed `text`, a row written by
-- any other writer with a non-UUID author made every read of that entry raise; the
-- column type is where that guarantee belongs, not in each reader.
--
-- value_ref and status are NOT NULL: `BlackboardEntryRow` types both as `str`, and
-- `resolve_after_conflict` compares value_refs to decide "converged" vs "conflict".
-- A NULL value_ref reaching that comparison reports a conflict won by a value that
-- does not exist. The repository still re-checks on read (defence in depth), but the
-- schema is what makes the state unrepresentable.
CREATE TABLE blackboard_entry (
    project_id    uuid NOT NULL,
    run_id        uuid NOT NULL,
    branch_id     text NOT NULL,
    author_agent  uuid NOT NULL,
    key           text NOT NULL,
    value_ref     text NOT NULL,
    status        text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, run_id, branch_id, key)
) PARTITION BY LIST (project_id);

-- invalidation_event: webhook/poller events with provenance selectors
-- (InvalidationPort, Phase 2). event_id is server-generated — the caller's
-- webhook payload never determines the row's identity.
CREATE TABLE invalidation_event (
    project_id  uuid NOT NULL,
    event_id    uuid NOT NULL DEFAULT gen_random_uuid(),
    event_type  text NOT NULL,
    selector    jsonb,
    fired_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, event_id)
) PARTITION BY LIST (project_id);

-- spend_ledger: rolled up by day/worker/model — SpendMeter.add accumulates
-- into this row via UPSERT (contract §5.4). Org-level billing rollup reads
-- across projects, which is the one explicitly exempted aggregation
-- (DECISIONS D-037 — billing metadata, not memory content).
CREATE TABLE spend_ledger (
    project_id  uuid NOT NULL,
    day         date NOT NULL,
    worker      text NOT NULL,
    model_id    text NOT NULL,
    tokens_in   bigint NOT NULL DEFAULT 0,
    tokens_out  bigint NOT NULL DEFAULT 0,
    cost_usd    numeric(14, 6) NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day, worker, model_id)
) PARTITION BY LIST (project_id);

-- review_queue: scan rejections and anything the state machine refuses to
-- auto-resolve (e.g. validated->retired below the K-distinct-principals
-- floor, DECISIONS D-021) land here for a human.
CREATE TABLE review_queue (
    project_id    uuid NOT NULL,
    item_id       uuid NOT NULL DEFAULT gen_random_uuid(),
    reason        text NOT NULL,
    memory_id     uuid,
    opened_at     timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    resolution    text,
    PRIMARY KEY (project_id, item_id)
) PARTITION BY LIST (project_id);

-- work_queue / dead_letter: UNPARTITIONED (contract §5.3 — at-least-once
-- SKIP LOCKED delivery; project_id rides in the row so consumers re-scope
-- themselves, no RLS GUC needed for a queue nothing reads by project). This
-- table shares Postgres's buffer cache with the vector index (PLAN.md §3
-- architecture note) — its xmin-horizon age is monitored for exactly that
-- reason, not enforced here.
CREATE TABLE work_queue (
    id                bigserial PRIMARY KEY,
    project_id        uuid NOT NULL,
    topic             text NOT NULL,
    payload           jsonb NOT NULL,
    priority          integer NOT NULL DEFAULT 100,
    available_at      timestamptz NOT NULL DEFAULT now(),
    lease_expires_at  timestamptz,
    attempts          integer NOT NULL DEFAULT 0,
    max_attempts      integer NOT NULL DEFAULT 5,
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- The exact access pattern of stores.pg.queue.WorkQueue.claim (contract
-- §5.3's SKIP LOCKED query): topic + available_at + lease_expires_at,
-- ordered by priority then id.
CREATE INDEX work_queue_claim_idx
    ON work_queue (topic, available_at, lease_expires_at, priority, id);

CREATE TABLE dead_letter (
    id                bigint PRIMARY KEY,
    project_id        uuid NOT NULL,
    topic             text NOT NULL,
    payload           jsonb NOT NULL,
    priority          integer NOT NULL,
    available_at      timestamptz NOT NULL,
    lease_expires_at  timestamptz,
    attempts          integer NOT NULL,
    max_attempts      integer NOT NULL,
    created_at        timestamptz NOT NULL,
    failed_at         timestamptz NOT NULL DEFAULT now(),
    last_error        text
);
