# PHASE-0.md — Trace substrate, isolation, and structural security

Execution order is dependency order; a task may start when its listed dependencies are green. No design decisions remain in this phase — where a choice appears below, it is the decision (cross-referenced to DECISIONS.md). All paths relative to repo root. Python 3.13, package `tracebed`, src layout (`src/tracebed/...`).

Conventions used throughout:
- `ProjectId`, `RunId`, `PrincipalId`, `MemoryId`, `AgentTypeId` are newtypes from Task 3 — never bare `str`/`UUID` in signatures.
- Every worker and every time-dependent test takes `clock: Clock` (Task 2) — no direct `datetime.now()` outside `SystemClock`.
- Tests live in `tests/phase0/`, marked `@pytest.mark.phase0`. The gate is `pytest -m phase0` plus the two CI scripts.

---

## Task 1 — Repo scaffold + license gate (must pass on commit one)
**Build:** `pyproject.toml` (py3.13; deps per DECISIONS D-036), `scripts/license_check.py`: walks the resolved dependency tree (`importlib.metadata`), classifies each distribution's license against `scripts/license_policy.toml` — allowlist `[PostgreSQL, Apache-2.0, BSD-2/3, MIT, ISC]`, conditional `[LGPL-3.0-only]` requiring an entry in the `lgpl_rationale` table (seeded with `psycopg`), denylist `[SSPL, BSL, RSAL, Elastic-2.0]`. Non-zero exit on unknown or denied. Wire as CI step 1. `docker/compose.yaml`: `pgvector/pgvector`-based **PG18** image with `pg_textsearch` installed, `valkey`, `seaweedfs` (S3 test target), api, dashboard placeholders.
**Files:** `pyproject.toml`, `scripts/license_check.py`, `scripts/license_policy.toml`, `docker/compose.yaml`, `.gitlab-ci.yml`/`.github/workflows/ci.yml`.
**Test:** CI run on the initial commit is green; adding a fake SSPL dist to a test fixture makes it fail.
**Depends on:** nothing.

## Task 2 — Typed config module + injectable clock
**Build:** `src/tracebed/domain/config.py` — `pydantic-settings`, env prefix `TB_`, nested models exactly:
```python
class TracebedSettings(BaseSettings):
    api: ApiConfig                # port: int = 8110, workers: int
    dashboard: DashboardConfig    # port: int = 8111
    auth: AuthConfig              # oidc_jwks_url: str | None, oidc_issuer: str | None,
                                  # api_key_mode: bool = True  (no unverified mode exists)
    storage: StorageConfig        # pg_dsn, valkey_url, tracestore: {driver: "fs"|"s3", root|bucket,endpoint,...}
    embedding: EmbeddingConfig    # model_id="gemini-embedding-2", model_version: str (required),
                                  # dim: int = 768, driver: "gemini"|"onnx-local", onnx_model_path/hash
    llm: LLMProviderConfig        # base_url, api_key_env, judge_model="gemini-3.1-pro",
                                  # distiller_model="gemini-3.1-pro", per_worker_overrides: dict
    retrieval: RetrievalConfig    # total_budget_ms=300, embed_timeout_ms=200, rrf_k=60,
                                  # rrf_weight_vector=1.0, rrf_weight_lexical=1.0, arm_top_n=50,
                                  # fused_top_n=20, hnsw_iterative_scan=True, hnsw_max_scan_tuples=20000
    abstention: AbstentionConfig  # cos_threshold=0.60, bm25_sat_k=10.0, bm25_norm_threshold=0.50,
                                  # rarity_min_shared_terms=2, rarity_max_df_pct=2.0, rarity_min_corpus_docs=200
    score: ScoreConfig            # w_sim=0.40, w_q=0.30, w_recency=0.15, w_validity=0.15, recency_half_life_days=14
    budget: BudgetConfig          # total_tokens=1200, static_prefix=700 (prefs=200, lessons=500),
                                  # dynamic=500, slot_caps={fact:250, exemplar:150, pitfall:100,
                                  # candidate_note:100, jit_lesson:150}
    scoring: ScoringConfig        # alpha=0.3, q_start=0.5, adapter_weights={verdict:1.0,
                                  # correction_adapter:0.8, downstream:0.3, implicit:0.0},
                                  # updates_per_memory_per_day=1
    promotion: PromotionConfig    # min_outcomes=2, failure_lesson_outcomes=1, min_distinct_principals=2
    retirement: RetirementConfig  # q_threshold=0.25, min_scored_uses=4, min_distinct_principals=3  # K
    lifecycle: LifecycleConfig    # decay_pct_per_idle_week=5, archive_floor=0.15,
                                  # quarantine_ttl_days=30, candidate_ttl_days=45, revalidation_age_days=30
    derived: DerivedConfig        # baseline_max_delta_pct=10, clamp_alert_consecutive=3,
                                  # divergence_alarm_pct=25, keep_versions=20
    proposals: ProposalConfig     # per_run_cap=2, per_project_daily_cap=50
    tier_a: TierAConfig           # candidate_cap_per_run=1
    killswitch: KillswitchConfig  # holdout_pct=5, salt_env="TB_HOLDOUT_SALT", window_days=14,
                                  # min_cell_n=200, correction="benjamini-hochberg"
    spend: SpendConfig            # daily_llm_cap_usd=25.0
    cache: CacheConfig            # ttl_class={"intel":"24h","registry":"14d"}
    session: SessionConfig        # idle_ttl_min=60, offload_threshold_tokens=20000
    queue: QueueConfig            # lease_seconds=30, max_attempts=5, batch_size=100
```
Layered resolution API: `ConfigResolver.effective(project_id, agent_type_id) -> EffectiveConfig` (process defaults → `project_config` → `agent_type_config` → `killswitch_state` overlay; overlay read-only). `src/tracebed/domain/clock.py`: `Clock` protocol, `SystemClock`, `FakeClock(advance(timedelta))`.
**Test:** defaults load with only `TB_STORAGE__PG_DSN` + `TB_EMBEDDING__MODEL_VERSION` set; env override works; unknown key rejected; resolver precedence proven with a fixture project override; `FakeClock.advance(days=2)` observed by a consumer.
**Depends on:** Task 1.

## Task 3 — Domain newtypes, event taxonomy, ScanVerdict type
**Build:** `src/tracebed/domain/ids.py`: `ProjectId`, `RunId` (UUIDv7 helpers: `mint_run_id()`), `PrincipalId`, `MemoryId`, `AgentTypeId` — distinct types under mypy strict; runtime constructors validate. `src/tracebed/domain/events.py`: `TraceEvent` union (`run_start | tool_call | tool_result | llm_call_meta | error | artifact_ref | state_note | run_end`) each with `ts`, `seq`; `FeedbackEvent` (`adapter`, `outcome: positive|negative`, `payload`, `event_id`, `occurred_at?` — **no weight field**); `MemoryProposal`. `src/tracebed/domain/scan.py`: `ScanVerdict` (opaque token: verdict id + content_hash + suite_version) — constructible only by `core/scans` (module-private constructor).
**Test:** mypy strict passes; `ScanVerdict` cannot be constructed from test code (constructor guard raises outside the scans module); UUIDv7 ids are time-ordered.
**Depends on:** Task 1.

## Task 4 — State machine + transition table
**Build:** `src/tracebed/domain/state_machine.py`: `Status` enum (`quarantined, candidate, validated, superseded, stale, retired, archived, pinned, tombstoned`), `TRANSITIONS: dict[tuple[Status, Status], Guard]` — exactly the table in PLAN.md §5, each `Guard` a named callable taking a `TransitionEvidence` dataclass (confirming run set + principals + input-sig clusters, promotion observations, strike count, TTL deadlines vs `clock`, provenance class); `apply(current, target, evidence) -> Status | IllegalTransition`. Proposal provenance class hard-codes `can_skip_shadow = False`.
**Test:** `tests/phase0/test_state_machine.py` — table-driven: every legal row with satisfying evidence passes; every legal row with deficient evidence (one principal short, same input-sig cluster, TTL not reached, proposal class trying a skip) is rejected; every pair not in the table is rejected (exhaustive product over Status×Status); `quarantined→validated` directly is illegal.
**Depends on:** Tasks 2, 3.

## Task 5 — Migrations: registries, epochs, embedding pin
**Build:** yoyo setup (`migrations/`), `0001_registries.sql`: `CREATE EXTENSION vector; CREATE EXTENSION pg_textsearch;` + `project`, `principal`, `agent_type`, `agent_registration` (UNIQUE(principal_id)), `embedding_model`, `scoring_epoch`, `project_config`, `agent_type_config`, `killswitch_state` — DDL per PLAN.md §5. Seed: `embedding_model` row from config pin.
**Test:** `yoyo apply` then `yoyo rollback` clean on the compose PG18; both extensions present; inserting a second `agent_registration` for one principal fails.
**Depends on:** Tasks 1, 2.

## Task 6 — Migrations: partitioned learning-plane tables + partition manager + RLS
**Build:** `0002_partitioned.sql`: `memory_item`, `memory_link`, `derived_state`, `trace_index` (with `submitter_principal NOT NULL`, `input_signature_hash NOT NULL`, `instrumentation_source`, `arm`, `outcome_status` incl. `incomplete`), `trace_subject`, `subject_key`, `outcome_event` (PK `(project_id, event_id)`, `principal_id NOT NULL`), `injection_log` (with `score`, `slot`, `injected_at`), `retrieval_event`, `blackboard_entry`, `invalidation_event`, `spend_ledger`, `review_queue` — all `PARTITION BY LIST (project_id)`, plus `work_queue`, `dead_letter` (unpartitioned). RLS: `ENABLE` + `FORCE ROW LEVEL SECURITY` on every partitioned table, policy `USING (project_id = current_setting('tracebed.project_id')::uuid)`; app role is not owner, no BYPASSRLS. `src/tracebed/stores/pg/partitions.py`: `create_project_partitions(conn, project_id)` — creates all per-project partitions + per-partition indexes (HNSW `halfvec_cosine_ops` on `memory_item.embedding`, BM25 index on `content`, btree on hot keys); `drop_project(conn, project_id)` — detach+drop across all tables in one transaction; `ensure_schema_current(conn)` — applies pending per-partition DDL to partitions created after a migration (first-party, replaces what yoyo can't see).
**Test:** create two projects → partitions exist; insert into each; `drop_project` removes one in a single transaction, other intact; direct SQL as app role without the GUC set returns zero rows from every partitioned table (RLS proof); `memory_item` insert with NULL `scan_verdict_id` fails (NOT NULL).
**Depends on:** Task 5.

## Task 7 — Typed repository + raw-SQL lint
**Build:** `src/tracebed/stores/pg/repo.py`: `Repo(pool, clock)`; every method's first parameter is `project_id: ProjectId`; each transaction begins `SET LOCAL tracebed.project_id = $1`. Builders (Phase 0 scope): `insert_memory_item(project_id, item: NewMemoryItem, scan_verdict: ScanVerdict)` — raises `ProvenanceIncomplete` unless `provenance.class` present with required fields per class (parser→trace_ids, distiller→trace_ids, human_verdict→verdict_id, proposal→run_id, operator→principal); `get_memory_by_id(project_id, memory_id)`; `upsert_trace_index`, `append_trace_subject`, `insert_outcome_event` (ON CONFLICT (project_id, event_id) DO NOTHING), `insert_injection_row`, `insert_retrieval_event`, `spend_add`, `register_agent`, `resolve_project(principal_id) -> ProjectScope`. **No method or constructor exists that omits `project_id`** except `resolve_project`. `scripts/raw_sql_lint.py`: AST walk over `src/`, fails on any `execute(`/SQL-string call outside `stores/pg/`; wire as CI step 2.
**Test:** provenance-rejection matrix (every class × missing field → `ProvenanceIncomplete`, row absent — invariant 6 test); by-id fetch with wrong project's id → `NotFound` (not data); lint fixture with a stray `conn.execute` in `api/` fails CI; grep-test asserts no public scope-less builder symbol is exported.
**Depends on:** Tasks 3, 4, 6.

## Task 8 — Auth: PrincipalPort, OIDC + API-key defaults, server-side scope derivation
**Build:** `src/tracebed/adapters/identity.py`: `PrincipalPort` protocol (`authenticate(request) -> Principal`); `OidcJwksVerifier` (RS256 against `auth.oidc_jwks_url`, iss/aud checks) and `ApiKeyVerifier` (constant-time hash compare against `principal.key_hash`). `src/tracebed/api/deps.py`: FastAPI dependency `scope = resolve_scope(principal)` → `Repo.resolve_project` → `ProjectScope{project_id, agent_type_id, principal_id}`; **no route reads project_id from the request**. `src/tracebed/api/admin.py`: `POST /admin/projects` (creates registry row + calls `create_project_partitions` + provisions project KEK), `POST /admin/agents/register` (principal↔project↔agent_type binding), `GET /admin/memory/{id}`, `GET /export/project` (streams only the caller's project). Minimal `api/main.py` on :8110.
**Test:** no credential → 401; valid API key → scope resolved from registry; a request body containing `project_id` is rejected (422, field forbidden); registration flow end-to-end creates partitions.
**Depends on:** Tasks 6, 7.

## Task 9 — Shared scan module (`core/scans`) with insert-side enforcement
**Build:** `src/tracebed/core/scans/__init__.py`: `scan(content: str, *, context: ScanContext) -> ScanResult` running: (a) injection-pattern scan (imperative phrasing heuristics, tool-invocation syntax, known prompt-injection markers — regex + rule set in `patterns.py`, versioned `suite_version`); (b) secret scan (key/token/credential patterns, high-entropy strings); (c) schema check (per mem_type field validation); (d) `tier_a_template.py`: closed-vocabulary template validator — renders Tier A notes exclusively from `TierANote(error_class: ErrorClassEnum, tool_id, tool_version, count, duration_ms, payload_class_hash)`; **no free-text parameter exists on the constructor**. `ScanResult.verdict() -> ScanVerdict` (the only constructor site). Rejections persist to `review_queue` with reason.
**Test:** seeded corpus `tests/fixtures/scan_corpus/` (imperative injections, tool-invocation strings, secrets, and the **Pydantic `input_value=` echo fixture**): 100% of strong-signal fixtures rejected; `TierANote` cannot carry a tool-error substring (compile-time: no str field; runtime: rendered note shares no ≥8-byte substring with the error-body fixture); `repo.insert_memory_item` without a `ScanVerdict` raises `TypeError` (signature) and a forged verdict fails hash check.
**Depends on:** Tasks 3, 7.

## Task 10 — Crypto-shredding: subject keys + envelope encryption
**Build:** `src/tracebed/crypto/shred.py`: `SubjectKeyManager(repo, master_key_provider)` — per-project KEK; `get_or_create_subject_kek(project_id, subject_tag)`; payload envelope format: trace payloads are JSON-lines *sections*, each section optionally tagged with subject_tags; section DEK (AES-256-GCM) wrapped under every referenced subject KEK (or project KEK if untagged); `destroy_subject(project_id, subject_tag)` sets `subject_key.destroyed_at` and zeroes the wrapped KEK — sections become permanently unreadable; reader returns `Tombstoned` sentinel for them.
**Test:** write payload with sections for subjects A and B → read back both; `destroy_subject(A)` → A's sections `Tombstoned`, B's readable, **stored object bytes unchanged** (hash compare pre/post), `trace_index.payload_ref` and memory provenance pointers still resolve.
**Depends on:** Tasks 6, 7.

## Task 11 — TraceStorePort: fs + S3 drivers
**Build:** `src/tracebed/stores/tracestore/` — `TraceStorePort` protocol: `put(project_id, run_id, seq_range, payload: EncryptedPayload) -> PayloadRef`, `get(project_id, ref) -> EncryptedPayload`, `exists`, `delete_project(project_id)`. `fs.py`: root layout `{root}/{project_id}/{run_id}/{first_seq:08d}.tbz`; `s3.py`: generic S3 (boto3-compatible via `httpx`+sigv4 or minimal boto3 — record in DECISIONS if boto3 added), key layout `tb/{project_id}/{run_id}/{first_seq:08d}`, SeaweedFS-tested; **no MinIO SDK** (legacy MinIO works because the driver speaks generic S3). All payloads pass through Task 10's envelope before `put`.
**Test:** round-trip fs (unit); round-trip S3 against compose SeaweedFS (integration mark); keys always embed project_id; `get` with another project's ref under the caller's project prefix → not found.
**Depends on:** Task 10.

## Task 12 — work_queue: SKIP LOCKED semantics
**Build:** `src/tracebed/stores/pg/queue.py`. Semantics (exact): producer `enqueue(topic, project_id, payload, priority=100, available_at=now)`. Consumer `claim(topic, n) `:
```sql
UPDATE work_queue SET lease_expires_at = now() + $lease, attempts = attempts + 1
WHERE id IN (SELECT id FROM work_queue
             WHERE topic = $1 AND available_at <= now()
               AND (lease_expires_at IS NULL OR lease_expires_at < now())
             ORDER BY priority, id
             FOR UPDATE SKIP LOCKED LIMIT $n)
RETURNING *;
```
`ack(id)` = DELETE; `nack(id, backoff)` = `available_at = now() + backoff`, lease cleared; lease expiry ⇒ automatic redelivery; `attempts > max_attempts` ⇒ move row to `dead_letter`. Delivery is at-least-once; **all consumers must be idempotent** (trace writer dedups on `(run_id, seq)`, outcome intake on `event_id`). Depth/age/dead-letter metrics exported; xmin-horizon age alarm (the queue shares buffer cache with the vector index — this is the monitored coupling).
**Test:** two concurrent consumers, 1,000 rows → zero double-acks; killed consumer's leases expire and redeliver; poison row lands in `dead_letter` after `max_attempts`; ordering respects priority then id.
**Depends on:** Task 6.

## Task 13 — SDK: fire-and-forget client with ring buffer
**Build:** `src/tracebed/sdk/client.py` + `buffer.py`. Exact surface:
```python
class TracebedClient:
    def __init__(self, base_url: str, *, api_key: str | None = None,
                 token_provider: Callable[[], str] | None = None,
                 buffer_capacity: int = 10_000, flush_interval_s: float = 1.0) -> None: ...
    def retrieve(self, *, agent_type: str, run_ctx: RunContext,
                 session_id: str | None = None,
                 prefetch_for: str | None = None) -> RetrieveResult: ...
        # sync HTTP; server-side budget 300ms; on ANY error/timeout returns
        # RetrieveResult(run_id=<sdk-minted uuid7, origin="sdk">, context_block=EMPTY, outcome_code="store_error")
        # — the SDK itself never raises from retrieve().  Phase 0: server stub returns empty block + minted run_id.
    def trace(self, run_id: RunId, event: TraceEvent) -> None: ...        # fire-and-forget, never raises, never blocks
    def feedback(self, run_id: RunId, event: FeedbackEvent) -> None: ...  # fire-and-forget, never raises
    def propose_memory(self, run_id: RunId, proposal: MemoryProposal) -> None: ...  # fire-and-forget; server activates Phase 4
    def on_operational_event(self, run_id: RunId, event: TraceEvent) -> ContextBlock | None: ...
        # JIT hook — Phase 0/1 returns None; trigger logic lands Phase 2 (CUTTABLE improvement 5)
    def run_end(self, run_id: RunId, status: Literal["ok","error","cancelled"]) -> None: ...
        # emits the run_end sentinel with final seq, then flush()
    def flush(self, timeout_s: float = 5.0) -> FlushReport: ...           # explicit drain; FlushReport(sent, dropped)
```
`RunContext = {query_text: str, workflow_template: str|None, user_ref: str|None, tool_manifest: list[str]|None}`. Buffer: in-process ring, monotonic per-run `seq` assigned at enqueue, drop-oldest at capacity with `dropped` counter (D-033), background flusher batching to `POST /v1/trace`. `RetrieveResult` / `ContextBlock` exactly per PLAN.md §3 (placement `append_last`, header exact).
**Test:** `trace()`/`feedback()` ≤1ms p99 on the fake runtime with the API **down**, zero exceptions; seq strictly monotonic per run; overflow drops oldest and counts; `run_end` flushes; `retrieve()` against a dead server returns the degraded result, never raises.
**Depends on:** Task 3 (types); server routes from Tasks 8, 14–15.

## Task 14 — Trace writer + trace_index (completeness detection)
**Build:** `src/tracebed/ingest/trace_writer.py`: consumes topic `trace_event`; batches per (project, run); encrypts sections via Task 10 (subject tags from `state_note`/`artifact_ref` events populate `trace_subject`); writes payload via TraceStorePort; upserts `trace_index` with `submitter_principal` (from the authenticated ingest context), `input_signature_hash` (= sha256 of sorted structured features ‖ 64-bit SimHash of `query_text` head — `domain/signatures.py`), `instrumentation_source="sdk"`, `arm` (echoed from retrieve, default `memory_on`); on `run_end` sentinel marks completeness; a sweeper (uses `clock`) marks runs with gaps or no sentinel after `2 × session.idle_ttl` as `outcome_status='incomplete'`. Idempotent on `(run_id, seq)`.
**API:** `POST /v1/trace` (202) — enqueue only, per PLAN.md §3 contract.
**Test:** fake-runtime run (start → 3 tool events → run_end) ⇒ complete queryable trace: `trace_index` row + payload readable + `trace_subject` rows; duplicate seq replay ⇒ no duplication; drop the sentinel, advance FakeClock ⇒ `incomplete`; `input_signature_hash` stable across event reordering.
**Depends on:** Tasks 10, 11, 12; route via Task 8's app.

## Task 15 — outcome_event intake (attach-by-run_id, days later)
**Build:** `src/tracebed/ingest/outcome_intake.py`: consumes topic `outcome_event`; validates adapter class; maps `outcome: positive|negative → r ∈ {1.0, 0.0}`; **derives `w` server-side from `scoring.adapter_weights`** (no weight accepted on the wire — 422 if present); records authenticated `principal_id`; inserts with `ON CONFLICT (project_id, event_id) DO NOTHING`; attaches by `run_id` regardless of arrival time (`occurred_at` may precede `arrived_at` by days); if the trace does not exist yet, the event still lands and joins later (no FK to trace_index — join is logical by (project_id, run_id)).
**API:** `POST /v1/feedback` (202).
**Test:** post trace at T, feedback at **T+2 simulated days** (FakeClock) ⇒ joined by run_id in a query; replay same `event_id` ⇒ exactly one row; payload with `weight` field ⇒ 422; `implicit` adapter ⇒ row recorded with w=0 flag, and (assert) zero rows in any Q-mutation table.
**Depends on:** Tasks 8, 12.

## Task 16 — injection_log + retrieval_event writers, spend_ledger skeleton
**Build:** `src/tracebed/stores/pg/telemetry.py`: `record_retrieval(project_id, run_id, outcome_code, latency_ms, embed_latency_ms, candidates_considered, top_score, arm)`; `record_injections(project_id, run_id, rows: list[InjectionRow])` (memory_id, slot, score, tokens). `src/tracebed/workers/spend.py`: `SpendMeter.add(project_id, worker, model_id, tokens_in, tokens_out, cost_usd)` rolling into `spend_ledger` by day; `check_cap(project_id) -> CapStatus` (Phase 3 enforces; skeleton only records). Phase 0 stub of `POST /v1/retrieve` (Task 8 app): authenticates, resolves scope, mints `run_id` (UUIDv7), writes `retrieval_event(outcome_code="empty_result")`, returns empty context_block with exact header and `placement="append_last"`.
**Test:** retrieve stub round-trip: 200, run_id is UUIDv7, retrieval_event row exists under the caller's project; spend rows accumulate and sum correctly by day.
**Depends on:** Tasks 7, 8.

## Task 17 — Cross-project leak suite (the Phase 0 security gate)
**Build:** `harness/leak_suite/` — fixtures create **two projects (A, B)** with registered principals, memories, traces, cache entries. Probes (each a test):
1. Search-path: A's principal runs every list/search route → zero B rows.
2. **By-id fetch:** A requests B's `memory_id`, `run_id`, `trace payload_ref`, `event_id` on every by-id route → 404/NotFound, never data, never a distinguishable error shape (same 404 body for "not yours" and "doesn't exist").
3. Admin endpoints: A's admin-scope principal hits `/admin/memory/{B-id}`, `/admin/projects/{B}` → 404.
4. Dashboard API: every dashboard route with A's token → zero B rows.
5. Export: `GET /export/project` as A → stream contains zero B identifiers (scan for B's uuids).
6. **Valkey collisions:** identical `tool_id`+`canonical_args`+`auth_context` cached in A and B → two distinct keys (assert key strings differ and embed each project_id); A's connection scoped-read of B's key pattern → empty; working-memory key for A's run unreadable via B's constructed key.
7. RLS bypass: raw SQL as the app role with no/wrong GUC → zero rows from all partitioned tables.
**Files:** `harness/leak_suite/test_leaks.py`, `src/tracebed/stores/valkey/keys.py` (key builders per PLAN.md §5 spec — the only place keys are constructed; grep-test asserts no `tb:` literal elsewhere).
**Test:** the suite **is** the deliverable; all seven probe classes green.
**Depends on:** Tasks 6, 7, 8, 11, 16, and the Valkey key module.

## Task 18 — Fake agent runtime + Phase 0 gate runner
**Build:** `harness/fake_runtime.py`: simulates N runs (retrieve → tool events → run_end → later feedback) against a live compose stack, measuring SDK call overhead; `harness/phase0_gate.py`: runs, in order — `pytest -m phase0`, `scripts/license_check.py`, `scripts/raw_sql_lint.py`, the leak suite, the fake-runtime overhead measurement — and emits `gate_report_phase0.md` with every assertion's pass/fail and the measured numbers.
**Test / Gate (all mechanically checked by the runner):**
- complete queryable trace per run; T+2-day feedback joins; replay-safe.
- leak suite: 0 leaks across all seven classes.
- scan corpus: 100% strong-signal rejection; insert-without-verdict raises; Tier A zero-passthrough proven.
- crypto-shred: destroy → tombstoned, bytes unchanged, provenance intact.
- state machine: full table coverage, all illegal transitions rejected.
- SDK overhead ≤1ms p99 with queue stopped; retrieve stub p99 reported.
- license + raw-SQL lint green.
**Depends on:** all previous tasks.

---

**STOP.** Present `gate_report_phase0.md` to the human. Do not begin Phase 1 without explicit approval.

Ordering-hazard reminders baked into the order above: the scan module (9) precedes every write path (14–16); registries/auth (5–8) precede all routes; the crypto envelope (10) precedes the first trace byte (11, 14); the state-machine table (4) precedes the repository (7); the license gate (1) is commit one, because psycopg fails the unamended allowlist.
