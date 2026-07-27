-- depends:

-- 0001_registries.sql — PHASE-0 Task 5 (docs/PHASE0-CONTRACT.md §1, §5.5; PLAN.md §5).
--
-- Registries, epochs, embedding pin, and the layered config store. Everything
-- here is small and unpartitioned by design: these rows are read on every
-- request (ConfigResolver.effective(), scope resolution) or written rarely
-- (admin provisioning). The learning plane — the tables that actually hold
-- project-scoped agent output and must be walled per invariant 4 — lives in
-- 0002_partitioned.sql, where RLS is added in 0003_rls.sql.

-- pgvector (halfvec ANN indexes, DECISIONS D-007) and vchord_bm25 (true BM25
-- lexical ranking, DECISIONS D-003). The originally-specified `pg_textsearch`
-- is a phantom — absent from the pinned image and not a real extension; the
-- image's BM25 engine is vchord_bm25 (+ its pg_tokenizer dependency, which is
-- why both are in shared_preload_libraries). BM25 *scoring* comes from
-- vchord_bm25; the abstention rarity gate's per-term document frequency
-- (PLAN.md §6 abstention.rarity_*) is counted off the `lexemes` tsvector column
-- via `@@` — an exact document frequency, which is the quantity the gate needs
-- (D-003 rejected ts_rank's *ranking*, not tsvector *matching*).
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_tokenizer;
CREATE EXTENSION IF NOT EXISTS vchord_bm25;

-- project: the registry root. deleted_at is a soft-delete marker only — the
-- actual removal of a project's learning-plane data happens through
-- stores.pg.partitions.drop_project (DETACH+DROP across every partitioned
-- table in one transaction), never by deleting this row (PLAN.md §5,
-- DECISIONS D-017: LIST partitioning as the lifecycle mechanism).
CREATE TABLE project (
    project_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text NOT NULL,
    status           text NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active', 'suspended', 'deleted')),
    retention_policy jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz
);

-- principal: an authenticated identity (adapters.identity.Principal mirrors
-- `kind`/`external_ref` exactly). project_id is never a column here — it is
-- derived from agent_registration below, never asserted by a caller
-- (invariant 4).
--
-- external_ref is UNIQUE on its own, NOT UNIQUE(kind, external_ref): the
-- repository's only lookup is `get_principal_by_external_ref(external_ref)`
-- (contract §5.1) with no `kind` argument, so a per-kind uniqueness
-- constraint would permit two rows one lookup cannot choose between —
-- e.g. an `oidc_sub` row (key_hash NULL) shadowing the `api_key` row whose
-- external_ref is the presented key's public key_id (C-19). Ambiguity in
-- the credential lookup is ambiguity in scope derivation, which is
-- invariant 4's root.
CREATE TABLE principal (
    principal_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         text NOT NULL CHECK (kind IN ('oidc_sub', 'api_key')),
    external_ref text NOT NULL,
    key_hash     text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz,
    UNIQUE (external_ref)
);

CREATE TABLE agent_type (
    agent_type_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid NOT NULL REFERENCES project (project_id),
    name          text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

-- agent_registration: THE isolation root (PLAN.md §5, DECISIONS D-017).
-- Repo.resolve_project(principal_id) derives project_id from this row —
-- the ONLY place project scope enters the system server-side. principal_id
-- is the PRIMARY KEY, which is strictly UNIQUE + NOT NULL: one principal can
-- never be registered against more than one (project, agent_type) — that
-- constraint is what stops "one caller, many projects" bypassing invariant 4
-- at the database level, not just in application code.
CREATE TABLE agent_registration (
    principal_id  uuid PRIMARY KEY REFERENCES principal (principal_id),
    project_id    uuid NOT NULL REFERENCES project (project_id),
    agent_type_id uuid NOT NULL REFERENCES agent_type (agent_type_id),
    registered_at timestamptz NOT NULL DEFAULT now()
);

-- embedding_model: the pin (DECISIONS D-007). Re-embedding is an explicit,
-- versioned migration — a new row plus a backfill job — never a silent
-- swap; mixed-model retrieval is refused by construction (a row can only
-- ever be stamped with one (model_id, model_version) pair).
CREATE TABLE embedding_model (
    model_id      text NOT NULL,
    model_version text NOT NULL,
    dim           integer NOT NULL CHECK (dim > 0 AND dim <= 768),
    provider      text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (model_id, model_version)
);

-- scoring_epoch: every Q update and shadow confirmation records epoch_id;
-- cross-epoch comparison is rejected (PLAN.md §5, errors.CrossEpochComparison
-- — raised starting Phase 3, but the table exists from Phase 0 so nothing
-- scored in an earlier phase ever lacks an epoch to point at).
CREATE TABLE scoring_epoch (
    epoch_id            integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    judge_model_id       text NOT NULL,
    judge_model_version  text NOT NULL,
    sampling_params      jsonb NOT NULL DEFAULT '{}'::jsonb,
    prompt_hash          text NOT NULL,
    started_at           timestamptz NOT NULL DEFAULT now()
);

-- project_config / agent_type_config: the layered override store behind
-- domain.config.ConfigResolver (contract §3.4, C-03 — dotted-path keys,
-- plain-JSON values; deployment-level sections are never overridable here,
-- ConfigResolver enforces that at effective() time, not the schema).
-- Unpartitioned: small, admin-write, read on every request.
CREATE TABLE project_config (
    project_id uuid NOT NULL REFERENCES project (project_id),
    key        text NOT NULL,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, key)
);

CREATE TABLE agent_type_config (
    project_id    uuid NOT NULL REFERENCES project (project_id),
    agent_type_id uuid NOT NULL REFERENCES agent_type (agent_type_id),
    key           text NOT NULL,
    value         jsonb NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, agent_type_id, key)
);

-- killswitch_state: read-only overlay to callers — ConfigResolver applies it
-- last and callers can never write killswitch_overlay through the config
-- surface (contract §3.4). agent_type_id is nullable: a NULL row is a
-- project-wide overlay for that mem_type. The partial-key uniqueness needs a
-- sentinel because a plain UNIQUE(project_id, agent_type_id, mem_type) would
-- let NULL agent_type_id collide silently (SQL NULLs never compare equal).
CREATE TABLE killswitch_state (
    project_id    uuid NOT NULL REFERENCES project (project_id),
    agent_type_id uuid REFERENCES agent_type (agent_type_id),
    mem_type      text NOT NULL
                      CHECK (mem_type IN ('episodic', 'semantic', 'lesson', 'preference')),
    disabled      boolean NOT NULL DEFAULT false,
    evidence      jsonb,
    changed_at    timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX killswitch_state_scope_uq
    ON killswitch_state (
        project_id,
        mem_type,
        COALESCE(agent_type_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );
