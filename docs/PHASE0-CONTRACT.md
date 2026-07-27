# PHASE0-CONTRACT.md — the binding cross-module contract

Eight coders build Phase 0 in parallel without seeing each other's work. This document is the
only shared surface. **It is binding**: if your implementation needs to deviate, you do not
deviate — you report a `contract_gap` and stop touching the boundary.

Authority order: PLAN.md > PHASE-0.md > this contract > your judgment. Where PLAN.md and
PHASE-0.md were silent or ambiguous, this document CHOOSES; every such choice is logged in §15
(numbered C-01…) and mirrors into DECISIONS.md at merge time. Where this contract resolves a
conflict, the resolution is noted inline with "CONFLICT:".

Conventions (restating the hard rules every chunk obeys):

- Python 3.13, `from __future__ import annotations` at the top of every file.
- mypy `--strict` clean. Domain newtypes (`ProjectId`, `RunId`, `PrincipalId`, `MemoryId`,
  `AgentTypeId` from `tracebed.domain.ids`) everywhere a bare `str`/`UUID` would otherwise appear.
- No SQL execution outside `src/tracebed/stores/pg/` (`scripts/raw_sql_lint.py`).
- No `tb:` literal outside `src/tracebed/stores/valkey/keys.py` (same lint).
- No `datetime.now()` outside `SystemClock`; every time-dependent component takes `clock: Clock`.
- All wire/enum string values are `enum.StrEnum` members whose `.value` IS the wire string.
- All Pydantic request/response models: `model_config = ConfigDict(extra="forbid")` — this is
  what makes a caller-supplied `project_id` or `weight` a 422 with zero extra code.
- Dataclasses crossing chunk boundaries are `@dataclass(frozen=True, slots=True)` unless stated.
- Tests: `tests/phase0/`, marked `@pytest.mark.phase0`. Anything touching Postgres/Valkey/S3 is
  ALSO marked `@pytest.mark.integration` and uses the skip fixtures from §13 — it must skip
  cleanly, never error at collection, when the service is absent.

---

## §1 MODULE MAP — every Phase 0 file, its owner chunk, its job

Chunks: `domain-config`, `domain-events-scan`, `domain-state-machine`, `migrations`, `repo`,
`queue`, `scans`, `crypto-tracestore`, `api-auth`, `sdk`, `ingest`, `telemetry`, `harness`.

Files marked **[frozen]** already exist and MUST NOT be modified by anyone.

| File | Chunk | Job |
|---|---|---|
| `pyproject.toml` | — | **[frozen]** deps, markers, mypy/ruff config |
| `scripts/license_check.py` `raw_sql_lint.py` `purity_check.py` | — | **[frozen]** CI gates |
| `scripts/license_policy.toml` | harness | allow/deny lists + `lgpl_rationale` seeded with psycopg (PHASE-0 Task 1) |
| `src/tracebed/__init__.py` | — | **[frozen]** |
| `src/tracebed/domain/ids.py` | — | **[frozen]** newtypes + uuid7 |
| `src/tracebed/domain/clock.py` | — | **[frozen]** Clock protocol |
| `src/tracebed/domain/errors.py` | domain-config | the full exception hierarchy (§3.1) |
| `src/tracebed/domain/config.py` | domain-config | TracebedSettings, EffectiveConfig, ConfigResolver (§3.4) |
| `src/tracebed/domain/enums.py` | domain-events-scan | every shared StrEnum (§3.2) |
| `src/tracebed/domain/scope.py` | domain-events-scan | ProjectScope (§3.3) |
| `src/tracebed/domain/canonical.py` | domain-events-scan | canonical_json, content_hash — THE one serialisation (§2) |
| `src/tracebed/domain/events.py` | domain-events-scan | TraceEvent union, FeedbackEvent, MemoryProposal, RunContext, RetrieveResult, ContextBlock/Slot, MEMORY_HEADER (§3.5) |
| `src/tracebed/domain/memory.py` | domain-events-scan | Provenance, NewMemoryItem, validate_provenance (§3.6) |
| `src/tracebed/domain/scan.py` | domain-events-scan | ScanVerdict type + caller-guarded constructor (§3.7) |
| `src/tracebed/domain/signatures.py` | domain-events-scan | input_signature_hash, simhash64, hamming (§3.8) |
| `src/tracebed/domain/state_machine.py` | domain-state-machine | Status, TransitionEvidence, TransitionLimits, TRANSITIONS, apply (§3.9) |
| `src/tracebed/adapters/__init__.py` | domain-events-scan | empty package init |
| `src/tracebed/adapters/ports.py` | domain-events-scan | ALL Protocols crossing chunk boundaries (§8) |
| `migrations/0001_registries.sql` | migrations | registries, epochs, embedding pin, config tables (Task 5) |
| `migrations/0002_partitioned.sql` | migrations | partitioned learning plane + RLS + work_queue/dead_letter (Task 6) |
| `src/tracebed/stores/__init__.py`, `stores/pg/__init__.py` | migrations | empty package inits |
| `src/tracebed/stores/pg/migrate.py` | migrations | yoyo runner wrapper (`apply_migrations(dsn)`) |
| `src/tracebed/stores/pg/partitions.py` | migrations | create_project_partitions, drop_project, ensure_schema_current (§5.5) |
| `src/tracebed/stores/pg/pool.py` | repo | `create_pool(dsn) -> psycopg_pool.ConnectionPool` |
| `src/tracebed/stores/pg/rows.py` | repo | frozen row dataclasses returned by Repo (§5.2) |
| `src/tracebed/stores/pg/repo.py` | repo | the typed repository — every builder (§5.1) |
| `src/tracebed/stores/pg/queue.py` | queue | WorkQueue (SKIP LOCKED) + TOPIC_* constants (§5.3) |
| `src/tracebed/stores/pg/telemetry.py` | telemetry | Telemetry facade: record_retrieval, record_injections (§5.4) |
| `src/tracebed/workers/__init__.py` | telemetry | empty package init |
| `src/tracebed/workers/spend.py` | telemetry | SpendMeter skeleton (§5.4) |
| `src/tracebed/core/__init__.py`, `core/scans/__init__.py` | scans | scan() entry point, verify_verdict (§4) |
| `src/tracebed/core/scans/patterns.py` | scans | injection/secret rule set, SUITE_VERSION |
| `src/tracebed/core/scans/tier_a_template.py` | scans | TierANote, ErrorClassEnum — no str fields (§4) |
| `src/tracebed/core/scans/_authority.py` | scans | process-local HMAC signing key (module-private) |
| `src/tracebed/crypto/__init__.py`, `crypto/shred.py` | crypto-tracestore | SubjectKeyManager, EncryptedPayload, envelope format (§6) |
| `src/tracebed/stores/tracestore/__init__.py` | crypto-tracestore | TraceStorePort, PayloadRef (§6.3) |
| `src/tracebed/stores/tracestore/fs.py` | crypto-tracestore | filesystem driver |
| `src/tracebed/stores/tracestore/s3.py` | crypto-tracestore | generic S3 driver (SeaweedFS target) |
| `src/tracebed/adapters/identity.py` | api-auth | Principal, PrincipalPort, OidcJwksVerifier, ApiKeyVerifier (§9.1) |
| `src/tracebed/api/__init__.py`, `api/deps.py` | api-auth | get_principal, get_scope, AppDeps (§9.2) |
| `src/tracebed/api/main.py` | api-auth | `create_app(settings, deps)`, `run()` entry point (C-30) |
| `src/tracebed/api/models.py` | api-auth | wire request/response models for `/v1/*` + `/admin/*` (C-28) |
| `src/tracebed/api/routes_v1.py` | api-auth | /v1/retrieve stub, /v1/trace(+/batch), /v1/feedback, /v1/propose_memory, /v1/invalidation (§9.3, C-31) |
| `src/tracebed/api/admin.py` | api-auth | /admin/*, /export/project (§9.3) |
| `src/tracebed/sdk/__init__.py`, `sdk/client.py`, `sdk/buffer.py` | sdk | TracebedClient, RingBuffer, FlushReport (§10) |
| `src/tracebed/ingest/__init__.py` | ingest | empty package init |
| `src/tracebed/ingest/trace_writer.py` | ingest | TraceWriter consumer + incomplete-sweeper (§11) |
| `src/tracebed/ingest/outcome_intake.py` | ingest | OutcomeIntake consumer (§11) |
| `src/tracebed/ingest/runner.py` | ingest | poll/dispatch loop + incomplete-sweep cadence (C-28) |
| `src/tracebed/stores/valkey/__init__.py`, `stores/valkey/keys.py` | harness | THE key builders — only `tb:` site (§7) |
| `src/tracebed/stores/valkey/client.py` | harness | ValkeyClient over the §7 key builders (C-28) |
| `harness/fake_runtime.py` | harness | N simulated runs, SDK overhead measurement (Task 18) |
| `harness/phase0_gate.py` | harness | gate runner → gate_report_phase0.md (Task 18) |
| `harness/leak_suite/test_leaks.py` | harness | the seven leak probes (Task 17) |
| `tests/phase0/conftest.py` | harness | shared fixtures + integration skip logic (§13.1) |
| `docker/compose.yaml`, CI workflow | harness | compose stack + CI steps (Task 1) |

Test-file ownership is §13.2. If a file is not in this table, it is not part of Phase 0 —
do not create it (test files per §13.2 and per-chunk `__init__.py`/`py.typed` excepted).

---

## §2 CANONICAL SERIALISATION AND HASHING — one function, one owner

Owner: `domain-events-scan`, file `src/tracebed/domain/canonical.py`. Everyone else imports;
nobody re-implements. This is what makes `content_hash`, `canonical_args`, and
`input_signature_hash` byte-identical across chunks.

```python
def canonical_json(obj: object) -> bytes:
    """json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8").
    Raises ValueError on non-JSON-serialisable input; NaN/Infinity rejected (allow_nan=False)."""

def content_hash(text: str) -> str:
    """sha256 hex digest of unicodedata.normalize("NFC", text).encode("utf-8").
    THE hash stored in memory_item.content_hash and bound into ScanVerdict."""

def sha256_hex(data: bytes) -> str: ...
def canonical_args(args: Mapping[str, object]) -> bytes:
    """= canonical_json(args); the tool-cache key input (§7)."""
```

- CHOICE (C-01): canonical JSON = `sort_keys=True`, separators `(",", ":")`, `ensure_ascii=False`,
  `allow_nan=False`, UTF-8. `content_hash` NFC-normalises first.

---

## §3 DOMAIN CONTRACTS

### §3.1 `domain/errors.py` — the full exception hierarchy (owner: domain-config)

Every cross-chunk raise/catch uses exactly these names. Phase annotations are informational;
ALL classes are defined in Phase 0 so later phases never touch this file's shape.

```python
class TracebedError(Exception):
    """Root. Every exception Tracebed raises deliberately derives from this."""

# -- config / wiring
class ConfigError(TracebedError): ...            # bad settings, unknown override key, bad layering

# -- auth / scope (api-auth raises; api layer maps to HTTP per §9.4)
class AuthenticationFailed(TracebedError): ...   # no/invalid credential -> 401
class ScopeResolutionFailed(TracebedError): ...  # authenticated but no agent_registration -> 403
class DuplicateRegistration(TracebedError): ...  # second agent_registration for a principal -> 409

# -- lookups
class NotFound(TracebedError):
    """By-id miss. Deliberately identical for 'does not exist' and 'not your project'
    (leak-suite probe 2: indistinguishable 404)."""

# -- write-side governance
class ProvenanceIncomplete(TracebedError): ...   # invariant 6; repo insert rejection
class ScanRejected(TracebedError):               # scan suite said no
    def __init__(self, reasons: Sequence[str]) -> None: ...
    reasons: tuple[str, ...]
class ScanVerdictForgery(TracebedError): ...     # bad HMAC, wrong caller module, content-hash mismatch

# -- state machine
class IllegalTransition(TracebedError):          # edge not in TRANSITIONS
    def __init__(self, current: Status | None, target: Status) -> None: ...
class GuardNotSatisfied(TracebedError):          # legal edge, deficient evidence
    def __init__(self, current: Status | None, target: Status, reason: str) -> None: ...

# -- queue / ingest
class QueueFull(TracebedError): ...              # producer-side hard cap (reserved; not raised Phase 0)

# -- crypto / trace store
class Tombstoned(TracebedError): ...             # API-level access to fully shredded material
class MasterKeyMissing(TracebedError): ...       # TB_MASTER_KEY absent/malformed at startup

# -- reserved for later phases (declared now, raised never in Phase 0):
class EmbeddingTimeout(TracebedError): ...       # Phase 1
class BudgetExceeded(TracebedError): ...         # Phase 1
class CapExceeded(TracebedError): ...            # Phase 3 (proposals / spend caps)
class CrossEpochComparison(TracebedError): ...   # Phase 3
```

`errors.py` is leaf-level: stdlib imports only, `Status` referenced as a string annotation
under `TYPE_CHECKING` — it must never import `state_machine` (everything imports errors).

### §3.2 `domain/enums.py` — shared enums and who owns which (owner: domain-events-scan)

All `enum.StrEnum`. These are THE wire strings and THE DB text values.

```python
class ProvenanceClass(StrEnum):
    PARSER = "parser"; DISTILLER = "distiller"; HUMAN_VERDICT = "human_verdict"
    PROPOSAL = "proposal"; OPERATOR = "operator"

class TrustTier(StrEnum): A = "A"; B = "B"
class MemType(StrEnum): EPISODIC = "episodic"; SEMANTIC = "semantic"; LESSON = "lesson"; PREFERENCE = "preference"
class Lane(StrEnum): OPERATIONAL = "operational"; QUALITY = "quality"
class ScopeType(StrEnum): AGENT_TYPE = "agent_type"; WORKFLOW_TEMPLATE = "workflow_template"; USER = "user"; PROJECT_SHARED = "project_shared"

class Slot(StrEnum):
    STATIC_PREFIX = "static_prefix"; FACT = "fact"; EXEMPLAR = "exemplar"
    PITFALL = "pitfall"; CANDIDATE_NOTE = "candidate_note"; JIT_LESSON = "jit_lesson"

class OutcomeCode(StrEnum):
    INJECTED = "injected"; ABSTAINED_THRESHOLD = "abstained_threshold"; ABSTAINED_RARITY = "abstained_rarity"
    EMPTY_RESULT = "empty_result"; DEGRADED_LEXICAL = "degraded_lexical"
    TIMEOUT_PREFIX_ONLY = "timeout_prefix_only"; STORE_ERROR = "store_error"; HOLDOUT = "holdout"

class AdapterClass(StrEnum): VERDICT = "verdict"; CORRECTION_ADAPTER = "correction_adapter"; DOWNSTREAM = "downstream"; IMPLICIT = "implicit"
class Arm(StrEnum): MEMORY_ON = "memory_on"; HOLDOUT = "holdout"
class InstrumentationSource(StrEnum): SDK = "sdk"; HOST_STREAM = "host_stream"

class TraceOutcomeStatus(StrEnum):       # trace_index.outcome_status
    PENDING = "pending"; OK = "ok"; ERROR = "error"; CANCELLED = "cancelled"; INCOMPLETE = "incomplete"
```

Enum ownership map (no other module defines an enum another chunk needs):
- `domain/enums.py`: everything above.
- `domain/state_machine.py`: `Status` only (§3.9).
- `core/scans/tier_a_template.py`: `ErrorClassEnum` only (§4) — scans-internal vocabulary.

### §3.3 `domain/scope.py` — ProjectScope (owner: domain-events-scan)

```python
@dataclass(frozen=True, slots=True)
class ProjectScope:
    """Server-side derived scope. The ONLY carrier of project identity from api to repo.
    Constructed in exactly two places: Repo.resolve_project and test fixtures."""
    project_id: ProjectId
    agent_type_id: AgentTypeId
    principal_id: PrincipalId
```

Flow (invariant 4): request → `api.deps.get_principal` (authenticates) →
`api.deps.get_scope` → `Repo.resolve_project(principal_id)` → `ProjectScope`. Route handlers
receive `scope: ProjectScope` and pass `scope.project_id` as the first argument to every repo /
telemetry / queue call. No route model contains a project_id field (extra="forbid" + no field).

### §3.4 `domain/config.py` (owner: domain-config)

Nested `pydantic-settings` models, `env_prefix="TB_"`, `env_nested_delimiter="__"`. Fields and
defaults exactly as PHASE-0 Task 2 (repeated here as the copy-paste source of truth):

```python
class ApiConfig(BaseModel):        port: int = 8110; workers: int = 2
class DashboardConfig(BaseModel):  port: int = 8111
class AuthConfig(BaseModel):
    oidc_jwks_url: str | None = None
    oidc_issuer: str | None = None
    api_key_mode: bool = True                  # no unverified mode exists
    admin_key_env: str = "TB_ADMIN_KEY"        # C-02: bootstrap admin key env var name
class TraceStoreConfig(BaseModel):
    driver: Literal["fs", "s3"] = "fs"
    root: Path = Path("./tracestore")          # fs driver
    bucket: str | None = None; endpoint: str | None = None; region: str = "us-east-1"
    access_key_env: str = "TB_S3_ACCESS_KEY"; secret_key_env: str = "TB_S3_SECRET_KEY"
class StorageConfig(BaseModel):
    pg_dsn: str                                # REQUIRED (TB_STORAGE__PG_DSN)
    valkey_url: str = "valkey://localhost:6379/0"
    tracestore: TraceStoreConfig = TraceStoreConfig()
class EmbeddingConfig(BaseModel):
    model_id: str = "gemini-embedding-2"
    model_version: str                         # REQUIRED (TB_EMBEDDING__MODEL_VERSION)
    dim: int = 768
    driver: Literal["gemini", "onnx-local"] = "gemini"
    onnx_model_path: Path | None = None; onnx_model_hash: str | None = None
class LLMProviderConfig(BaseModel):
    base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai/"
    api_key_env: str = "TB_LLM_API_KEY"
    judge_model: str = "gemini-3.1-pro"; distiller_model: str = "gemini-3.1-pro"
    per_worker_overrides: dict[str, str] = {}
class RetrievalConfig(BaseModel):
    total_budget_ms: int = 300; embed_timeout_ms: int = 200; rrf_k: int = 60
    rrf_weight_vector: float = 1.0; rrf_weight_lexical: float = 1.0
    arm_top_n: int = 50; fused_top_n: int = 20
    hnsw_iterative_scan: bool = True; hnsw_max_scan_tuples: int = 20_000
class AbstentionConfig(BaseModel):
    cos_threshold: float = 0.60; bm25_sat_k: float = 10.0; bm25_norm_threshold: float = 0.50
    rarity_min_shared_terms: int = 2; rarity_max_df_pct: float = 2.0; rarity_min_corpus_docs: int = 200
class ScoreConfig(BaseModel):
    w_sim: float = 0.40; w_q: float = 0.30; w_recency: float = 0.15; w_validity: float = 0.15
    recency_half_life_days: int = 14
class BudgetConfig(BaseModel):
    total_tokens: int = 1200
    static_prefix: int = 700; static_prefix_prefs: int = 200; static_prefix_lessons: int = 500
    dynamic: int = 500
    slot_caps: dict[str, int] = {"fact": 250, "exemplar": 150, "pitfall": 100,
                                 "candidate_note": 100, "jit_lesson": 150}
class ScoringConfig(BaseModel):
    alpha: float = 0.3; q_start: float = 0.5
    adapter_weights: dict[str, float] = {"verdict": 1.0, "correction_adapter": 0.8,
                                         "downstream": 0.3, "implicit": 0.0}
    updates_per_memory_per_day: int = 1
class PromotionConfig(BaseModel):
    min_outcomes: int = 2; failure_lesson_outcomes: int = 1; min_distinct_principals: int = 2
class RetirementConfig(BaseModel):
    q_threshold: float = 0.25; min_scored_uses: int = 4; min_distinct_principals: int = 3   # K
class LifecycleConfig(BaseModel):
    decay_pct_per_idle_week: float = 5; archive_floor: float = 0.15
    quarantine_ttl_days: int = 30; candidate_ttl_days: int = 45; revalidation_age_days: int = 30
class DerivedConfig(BaseModel):
    baseline_max_delta_pct: float = 10; clamp_alert_consecutive: int = 3
    divergence_alarm_pct: float = 25; keep_versions: int = 20
class ProposalConfig(BaseModel):   per_run_cap: int = 2; per_project_daily_cap: int = 50
class TierAConfig(BaseModel):      candidate_cap_per_run: int = 1
class KillswitchConfig(BaseModel):
    holdout_pct: float = 5; salt_env: str = "TB_HOLDOUT_SALT"; window_days: int = 14
    min_cell_n: int = 200; correction: str = "benjamini-hochberg"
class SpendConfig(BaseModel):      daily_llm_cap_usd: float = 25.0
class CacheConfig(BaseModel):      ttl_class: dict[str, str] = {"intel": "24h", "registry": "14d"}
class SessionConfig(BaseModel):    idle_ttl_min: int = 60; offload_threshold_tokens: int = 20_000
class QueueConfig(BaseModel):      lease_seconds: int = 30; max_attempts: int = 5; batch_size: int = 100

class TracebedSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TB_", env_nested_delimiter="__", extra="forbid")
    api: ApiConfig = ApiConfig()
    dashboard: DashboardConfig = DashboardConfig()
    auth: AuthConfig = AuthConfig()
    storage: StorageConfig                     # required member (pg_dsn)
    embedding: EmbeddingConfig                 # required member (model_version)
    llm: LLMProviderConfig = LLMProviderConfig()
    retrieval: RetrievalConfig = RetrievalConfig()
    abstention: AbstentionConfig = AbstentionConfig()
    score: ScoreConfig = ScoreConfig()
    budget: BudgetConfig = BudgetConfig()
    scoring: ScoringConfig = ScoringConfig()
    promotion: PromotionConfig = PromotionConfig()
    retirement: RetirementConfig = RetirementConfig()
    lifecycle: LifecycleConfig = LifecycleConfig()
    derived: DerivedConfig = DerivedConfig()
    proposals: ProposalConfig = ProposalConfig()
    tier_a: TierAConfig = TierAConfig()
    killswitch: KillswitchConfig = KillswitchConfig()
    spend: SpendConfig = SpendConfig()
    cache: CacheConfig = CacheConfig()
    session: SessionConfig = SessionConfig()
    queue: QueueConfig = QueueConfig()
```

(Mutable defaults above are shorthand — implement with `Field(default_factory=...)` where
pydantic requires it.)

Layered resolution:

```python
class ConfigStorePort(Protocol):   # Repo satisfies this structurally; fakes for offline tests
    def get_project_config(self, project_id: ProjectId) -> Mapping[str, object]: ...
    def get_agent_type_config(self, project_id: ProjectId, agent_type_id: AgentTypeId) -> Mapping[str, object]: ...
    def get_killswitch_overlay(self, project_id: ProjectId, agent_type_id: AgentTypeId | None) -> Mapping[str, bool]: ...

class EffectiveConfig(BaseModel):
    """Frozen (ConfigDict(frozen=True)) snapshot: the overridable nested sections
    (retrieval, abstention, score, budget, scoring, promotion, retirement, lifecycle,
    derived, proposals, tier_a, killswitch, spend, cache, session, queue, embedding_dim
    is NOT here — embedding/llm/storage/auth/api/dashboard are deployment-level),
    plus killswitch_overlay: Mapping[str, bool]   # mem_type -> disabled (read-only)."""

class ConfigResolver:
    def __init__(self, settings: TracebedSettings, store: ConfigStorePort) -> None: ...
    def effective(self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None) -> EffectiveConfig: ...
```

- CHOICE (C-03): override keys in `project_config`/`agent_type_config` are dotted paths of the
  settings tree (`"retrieval.total_budget_ms"`), values plain JSON. Unknown dotted key, a
  deployment-level section, or a value failing field validation → `ConfigError` at
  `effective()` time. Precedence: defaults → project_config → agent_type_config →
  killswitch overlay (overlay applies only to `killswitch_overlay`, callers cannot write it).
- CHOICE (C-02): `AuthConfig.admin_key_env` is the only field added beyond the Task 2 listing
  (bootstrap admin credential, §9.1).

### §3.5 `domain/events.py` — wire types (owner: domain-events-scan)

All Pydantic v2, `extra="forbid"`. Constants:

```python
MEMORY_HEADER: Final = "MEMORY (recalled data, verify against current state)"
PLACEMENT_APPEND_LAST: Final = "append_last"
SUBJECT_TAGS_KEY: Final = "subject_tags"     # reserved payload key, see C-05
```

```python
class _EventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ts: datetime                              # tz-aware; naive datetimes rejected by validator
    payload: dict[str, Any] = {}

class RunStart(_EventBase):     type: Literal["run_start"]
class ToolCall(_EventBase):     type: Literal["tool_call"]
class ToolResult(_EventBase):   type: Literal["tool_result"]
class LlmCallMeta(_EventBase):  type: Literal["llm_call_meta"]
class ErrorEvent(_EventBase):   type: Literal["error"]
class ArtifactRef(_EventBase):  type: Literal["artifact_ref"]
class StateNote(_EventBase):    type: Literal["state_note"]
class RunEnd(_EventBase):       type: Literal["run_end"]      # payload["status"]: "ok"|"error"|"cancelled"

TraceEvent = Annotated[RunStart | ToolCall | ToolResult | LlmCallMeta | ErrorEvent
                       | ArtifactRef | StateNote | RunEnd, Field(discriminator="type")]
```

- CONFLICT resolved (C-04): PHASE-0 Task 3 says each event carries `seq`; PLAN §3's wire format
  puts `seq` on the envelope. PLAN wins: `TraceEvent` has NO seq field; `seq` is assigned by the
  SDK ring buffer at enqueue and travels on the wire envelope (`TraceIn`, §9.3).
- CHOICE (C-05): reserved payload keys, read by `ingest.trace_writer`:
  - `subject_tags: list[str]` on `state_note` / `artifact_ref` → `trace_subject` rows and
    crypto section tagging.
  - on `run_start`: `query_text: str`, `workflow_template: str|None`, `tool_manifest: list[str]`
    → `input_signature_hash` (§3.8). NOTE (D-098, 2026-07-26): the `arm` key still rides on
    the `run_start` payload and `ingest.trace_writer` NO LONGER READS IT. `trace_index.arm`
    is derived inside `Repo`'s upsert from `retrieval_event.arm` — the value the server
    itself assigned — because PLAN.md §10 forbids accepting an arm assignment from any
    caller, and a caller-relayed arm is a caller-asserted one. `TraceIndexUpsert` no longer
    carries an `arm` field at all.
  - on `run_end`: `status` → `trace_index.outcome_status` (ok|error|cancelled).

```python
class FeedbackEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")   # a `weight` key -> 422; no weight field EXISTS
    adapter: AdapterClass
    outcome: Literal["positive", "negative"]
    payload: dict[str, Any] = {}
    event_id: UUID                              # dedup key
    occurred_at: datetime | None = None

class MemoryProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mem_type: Literal["lesson", "semantic"]
    content: str
    subject_tag: str | None = None
    claimed_scope: Literal["agent_type", "project_shared"]

class RunContext(BaseModel):                    # SDK-side (Task 13); api maps to wire (§9.3)
    model_config = ConfigDict(extra="forbid")
    query_text: str
    workflow_template: str | None = None
    user_ref: str | None = None
    tool_manifest: list[str] | None = None

class ContextSlot(BaseModel):
    slot: Slot; memory_id: UUID | None; tokens: int; text: str

class ContextBlock(BaseModel):
    placement: Literal["append_last"] = PLACEMENT_APPEND_LAST
    header: str = MEMORY_HEADER
    slots: list[ContextSlot] = []
    rendered: str = ""                          # byte-stable for a given slot list

def empty_context_block() -> ContextBlock: ...  # slots=[], rendered=""

class RetrieveResult(BaseModel):
    run_id: UUID
    run_id_origin: Literal["server", "sdk"] = "server"
    arm: Arm
    outcome_code: OutcomeCode
    context_block: ContextBlock
```

Wire models carry plain `UUID`; the newtypes wrap at the domain/repo boundary, not on the wire.

### §3.6 `domain/memory.py` — Provenance, NewMemoryItem (owner: domain-events-scan)

```python
@dataclass(frozen=True, slots=True)
class Provenance:
    cls: ProvenanceClass
    trace_ids: tuple[RunId, ...] = ()
    verdict_id: UUID | None = None
    tool_refs: tuple[str, ...] = ()
    input_sig_hashes: tuple[bytes, ...] = ()
    run_id: RunId | None = None                 # proposal class
    principal: PrincipalId | None = None        # operator class
    def to_json(self) -> dict[str, object]: ...
    @classmethod
    def from_json(cls, raw: Mapping[str, object]) -> Provenance: ...

def validate_provenance(p: Provenance) -> None:
    """Raises ProvenanceIncomplete unless the class's required fields are present:
    parser -> trace_ids non-empty; distiller -> trace_ids non-empty;
    human_verdict -> verdict_id; proposal -> run_id; operator -> principal.
    Pure — the offline half of invariant 6. Repo.insert_memory_item calls it; the DB
    NOT NULL / jsonb checks backstop it."""

@dataclass(frozen=True, slots=True)
class NewMemoryItem:
    scope_type: ScopeType
    scope_id: UUID | None                       # None only for PROJECT_SHARED
    mem_type: MemType
    kind: str
    lane: Lane
    trust_tier: TrustTier
    status: Status                              # initial status from state_machine.apply(None, ...)
    content: str
    token_count: int
    provenance: Provenance
    subject_tag: str | None = None
    cluster_id: UUID | None = None
    ttl_class: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    schema_version: int = 1
    id: MemoryId | None = None                  # None -> repo mints via mint_memory_id()
```

`provenance` jsonb on-disk shape (fixed): `{"class": ..., "trace_ids": [...], "verdict_id":
..., "tool_refs": [...], "input_sig_hashes": ["<hex>", ...], "run_id": ..., "principal": ...}`
— absent optionals omitted, ids as canonical UUID strings, hashes hex.

### §3.7 `domain/scan.py` — ScanVerdict and forgery resistance (owner: domain-events-scan)

The mechanism (C-06), decided end-to-end so `scans`, `repo`, and test authors agree:

1. `ScanVerdict` is a frozen dataclass: `verdict_id: UUID`, `content_hash: str` (§2),
   `suite_version: str`, `issued_at_ms: int`, `sig: bytes`.
2. Its `__post_init__` runs a caller-module guard: walk `sys._getframe` outward past
   dataclass/`domain.scan` internals; unless the instantiating module's `__name__` starts with
   `"tracebed.core.scans"`, raise `ScanVerdictForgery`. This satisfies Task 3's test
   ("cannot be constructed from test code") without core/scans even existing yet.
3. `sig` = HMAC-SHA256 over `verdict_id.bytes + content_hash.encode() + suite_version.encode()
   + issued_at_ms.to_bytes(8, "big")`, keyed by a process-local random key in
   `core/scans/_authority.py` (`_SIGNING_KEY: bytes = secrets.token_bytes(32)`, module-private,
   generated at import). Verdicts are valid only within the issuing process — acceptable in
   Phase 0 because scan and insert always happen in the same process; if a later phase separates
   them, that is a contract_gap, not a workaround.
4. Verification is scans-owned (repo imports scans; scans NEVER imports repo):
   `core.scans.verify_verdict(verdict: ScanVerdict, expected_content_hash: str) -> None`
   raises `ScanVerdictForgery` on HMAC mismatch OR `verdict.content_hash != expected_content_hash`.
   `Repo.insert_memory_item` computes `content_hash(item.content)` and calls this before insert.

`domain/scan.py` exports `ScanVerdict` + the guard; it does NOT hold the key (domain stays
pure; the key lives with the minting authority).

### §3.8 `domain/signatures.py` (owner: domain-events-scan)

```python
SIMHASH_HEAD_CHARS: Final = 512
SAME_CLUSTER_MAX_HAMMING: Final = 8            # D-020
SIG_HASH_LEN: Final = 40                       # 32 sha256 bytes + 8 simhash bytes
ABSENT_SIGNATURE: Final = bytes(40)            # C-07: run with no run_start (sweeper fallback)

def simhash64(text: str) -> int:
    """64-bit SimHash over 3-gram character shingles of the NFC-normalised, casefolded,
    whitespace-collapsed first SIMHASH_HEAD_CHARS chars. Empty text -> 0.
    Per-shingle hash: first 8 bytes (big-endian) of sha256(shingle.encode("utf-8"))."""

def hamming(a: int, b: int) -> int: ...
def same_cluster(a: bytes, b: bytes) -> bool:
    """Trailing 8 simhash bytes of two SIG_HASH_LEN signatures; Hamming <= SAME_CLUSTER_MAX_HAMMING."""

def input_signature_hash(*, agent_type_id: AgentTypeId,
                         query_text: str,
                         workflow_template: str | None,
                         tool_manifest: Sequence[str] | None) -> bytes:
    """The exact feature set (C-07): sha256(canonical_json({
         "agent_type": str(agent_type_id),
         "workflow_template": workflow_template or "",
         "tool_manifest": sorted(tool_manifest or []),
       })) + simhash64(query_text).to_bytes(8, "big").  Always SIG_HASH_LEN bytes.
    Independent of event order/timing by construction -> Task 14's reordering-stability test."""
```

### §3.9 `domain/state_machine.py` (owner: domain-state-machine)

```python
class Status(StrEnum):
    QUARANTINED = "quarantined"; CANDIDATE = "candidate"; VALIDATED = "validated"
    SUPERSEDED = "superseded"; STALE = "stale"; RETIRED = "retired"
    ARCHIVED = "archived"; PINNED = "pinned"; TOMBSTONED = "tombstoned"

RETRIEVABLE_STATUSES: Final = frozenset({Status.VALIDATED, Status.CANDIDATE, Status.PINNED})
# candidate: Tier A only, cap 1/run, labeled; pinned: prefix only — enforced Phase 1.

@dataclass(frozen=True, slots=True)
class ShadowConfirmation:
    run_id: RunId
    principal_id: PrincipalId
    input_signature_hash: bytes                 # SIG_HASH_LEN bytes

@dataclass(frozen=True, slots=True)
class TransitionLimits:
    """Threshold snapshot so the machine never reads config or DB."""
    quarantine_ttl_days: int; candidate_ttl_days: int
    promote_min_outcomes: int; failure_lesson_outcomes: int; promotion_min_distinct_principals: int
    retire_q_threshold: float; retire_min_scored_uses: int; retire_min_distinct_principals: int
    archive_floor: float
    @classmethod
    def from_config(cls, cfg: EffectiveConfig) -> TransitionLimits: ...

@dataclass(frozen=True, slots=True)
class TransitionEvidence:
    """Every field any guard in the PLAN §5 table inspects. Guards read only their own
    fields and reject on absence — a missing field is never a default-pass."""
    now: datetime                               # from clock; guards never call clocks
    provenance_class: ProvenanceClass
    trust_tier: TrustTier
    mem_type: MemType
    is_failure_lesson: bool = False
    scan_passed: bool = False
    scan_repass: bool = False
    provenance_complete: bool = False
    status_changed_at: datetime | None = None   # TTL guards measure from here
    # quarantined -> candidate
    confirmations: tuple[ShadowConfirmation, ...] = ()
    has_verified_human_verdict: bool = False
    # candidate -> validated
    promotion_outcomes: int = 0
    promotion_distinct_principals: int = 0
    outcome_consistent: bool = False
    open_contradiction: bool = False
    # contradiction / supersession
    contradiction_equal_or_stronger: bool = False   # validated -> superseded
    contradiction_weaker_provenance: bool = False   # candidate -> quarantined
    scan_reflag: bool = False
    # staleness / retirement / decay
    invalidation_event: bool = False
    ttl_class_expired: bool = False
    revalidation_failed: bool = False
    reverified: bool = False
    strike_count: int = 0
    q_value: float = 0.0
    scored_use_count: int = 0
    distinct_scoring_principals: int = 0
    decay_floor_reached: bool = False
    # operator / erasure
    operator_restore: bool = False
    operator_created: bool = False              # empty -> pinned
    erasure_or_approved_delete: bool = False

@dataclass(frozen=True, slots=True)
class GuardOutcome:
    ok: bool
    reason: str                                 # becomes GuardNotSatisfied.reason

Guard = Callable[[TransitionEvidence, TransitionLimits], GuardOutcome]

TRANSITIONS: Final[dict[tuple[Status | None, Status], Guard]]
# Exactly the PLAN §5 table; `None` is the empty pre-insert state. The wildcard
# "any non-terminal -> tombstoned" is materialised as an explicit entry for EVERY status
# except TOMBSTONED (C-08: retired/superseded/archived can still be erased — erasure must
# reach everything that is not already a tombstone).

def apply(current: Status | None, target: Status,
          evidence: TransitionEvidence, limits: TransitionLimits) -> Status:
    """Returns `target` iff (current, target) is a legal edge AND its guard passes.
    Raises IllegalTransition for edges not in TRANSITIONS (incl. quarantined->validated).
    Raises GuardNotSatisfied(current, target, reason) when the edge exists but evidence is
    deficient. There is NO other way to compute a status change (invariant 7)."""

def independent_confirmations(confirmations: Sequence[ShadowConfirmation]) -> int:
    """Size of the largest subset with pairwise-distinct principal_ids AND pairwise-distinct
    input-signature clusters (same_cluster, §3.8)."""
```

Guard semantics pinned (so parallel coders implement identical guards):
- Entry edges: `None→candidate` = tier A + class PARSER + scan_passed + provenance_complete.
  `None→quarantined` = tier B + class in {DISTILLER, PROPOSAL} + scan_passed +
  provenance_complete. `None→pinned` = class OPERATOR + operator_created + mem_type PREFERENCE.
- `quarantined→candidate` = `independent_confirmations >= 2` (>= failure_lesson_outcomes,
  i.e. 1, when is_failure_lesson) OR (has_verified_human_verdict AND class == HUMAN_VERDICT
  provenance route). For `provenance_class == PROPOSAL` BOTH routes return not-ok
  unconditionally (D-023; hard-coded, not configurable).
- TTL guards compare `now - status_changed_at` to the limit; `status_changed_at is None` →
  GuardNotSatisfied.
- `candidate→validated` = promotion_outcomes >= promote_min_outcomes AND
  promotion_distinct_principals >= promotion_min_distinct_principals AND outcome_consistent
  AND scan_repass AND NOT open_contradiction.
- `validated→retired` = q_value < retire_q_threshold AND scored_use_count >=
  retire_min_scored_uses AND distinct_scoring_principals >= retire_min_distinct_principals.
  The "otherwise → review_queue" branch is the CALLER's job (Phase 3 workers) — the machine
  only refuses.
- `stale→retired` = strike_count >= 2. `stale→validated` = reverified.
- `archived→validated` = operator_restore. `*→tombstoned` = erasure_or_approved_delete.
- `pinned` participates in exactly: `None→pinned`, `pinned→tombstoned`.

---

## §4 `core/scans` — the shared gate suite (owner: scans)

```python
# core/scans/__init__.py
SUITE_VERSION: Final[str]                      # e.g. "scans/1.0.0"; bump on any rule change

@dataclass(frozen=True, slots=True)
class ScanContext:
    project_id: ProjectId
    mem_type: MemType
    trust_tier: TrustTier
    provenance_class: ProvenanceClass
    lane: Lane

@dataclass(frozen=True, slots=True)
class ScanResult:
    passed: bool
    reasons: tuple[str, ...]                   # empty iff passed; e.g. "injection:imperative", "secret:aws-key"
    content_hash: str                          # §2 content_hash of the scanned content
    suite_version: str
    def verdict(self) -> ScanVerdict:
        """THE ONLY ScanVerdict constructor site. Raises ScanRejected(reasons) if not passed."""

def scan(content: str, *, context: ScanContext) -> ScanResult:
    """Runs, in order: injection-pattern scan, secret scan, per-mem_type schema check.
    Pure function — NO I/O, NO repo import. Persisting a rejection to review_queue is the
    CALLER's job via repo.insert_review_item (keeps scans importable from anywhere,
    including hotpath in Phase 1)."""

def verify_verdict(verdict: ScanVerdict, expected_content_hash: str) -> None:
    """HMAC + content-hash check (§3.7). Raises ScanVerdictForgery."""
```

```python
# core/scans/tier_a_template.py
class ErrorClassEnum(StrEnum):
    TIMEOUT = "timeout"; RATE_LIMITED = "rate_limited"; AUTH_DENIED = "auth_denied"
    SCHEMA_VALIDATION = "schema_validation"; TOOL_UNAVAILABLE = "tool_unavailable"
    NETWORK = "network"; SERVER_ERROR = "server_error"; CANCELLED = "cancelled"
    RESOURCE_EXHAUSTED = "resource_exhausted"; UNKNOWN = "unknown"

@dataclass(frozen=True, slots=True)
class TierANote:
    """Closed vocabulary by construction (D-019). NO free-text str parameter exists.
    tool_id/tool_version are validated against ^[A-Za-z0-9_.:-]{1,128}$ at __post_init__
    (identifier charset — cannot smuggle prose); payload_class_hash is validated hex."""
    error_class: ErrorClassEnum
    tool_id: str                               # identifier-validated, not prose
    tool_version: str                          # identifier-validated
    count: int
    duration_ms: int
    payload_class_hash: str                    # sha256 hex of the payload *schema class*, never content

def render_note(note: TierANote) -> str:
    """Deterministic template rendering. Gate test: rendered output shares no >=8-byte
    substring with any tool-error-body fixture."""
```

Corpus: `tests/fixtures/scan_corpus/` (owner: scans) — layout: `strong_injection/*.txt`,
`secrets/*.txt`, `benign/*.txt`, plus the Pydantic `input_value=` echo fixture at
`strong_injection/pydantic_input_value_echo.txt`. 100% of `strong_injection/` + `secrets/`
must be rejected; `benign/` must pass (false-positive canary, not a gate number).

---

## §5 `stores/pg` — repository, queue, telemetry, partitions

### §5.0 Connection and transaction ownership (binding for every chunk)

- `pool.py` (owner: repo): `def create_pool(dsn: str, *, min_size: int = 1, max_size: int = 10)
  -> psycopg_pool.ConnectionPool`. Everyone gets connections through Repo/WorkQueue — no other
  chunk touches the pool directly.
- **Repo owns transactions.** Every public Repo method opens its own connection + transaction
  and is atomic on its own. For multi-statement units there is exactly one composition tool:

```python
class Repo:
    def __init__(self, pool: ConnectionPool, clock: Clock) -> None: ...
    @contextmanager
    def tx(self, project_id: ProjectId) -> Iterator[ScopedRepo]:
        """One transaction, GUC set once at entry; yields a handle exposing the same
        builders WITHOUT the project_id parameter (it is bound). Used by ingest
        (trace_index + trace_subject atomically) and partitions.drop_project."""
```

- **The GUC.** `SET LOCAL` cannot take a bind parameter, so the one blessed statement —
  executed as the FIRST statement inside every transaction that touches a partitioned table —
  is (C-09):

```sql
SELECT set_config('tracebed.project_id', %(project_id)s, true);   -- true => transaction-local
```

  Registry-only methods (project/principal/agent_type/agent_registration/embedding_model/
  scoring_epoch — unpartitioned tables) skip the GUC. Every partitioned-table path sets it.
  RLS (FORCE) is the backstop that makes forgetting it return zero rows, not other tenants'.

### §5.1 `stores/pg/repo.py` — every Phase 0 builder (owner: repo)

First parameter `project_id: ProjectId` on every partitioned-table builder. The ONLY methods
without it are the registry methods marked [registry] below — the grep-test allowlist is
exactly: `resolve_project`, `create_project`, `create_principal`, `get_principal_by_external_ref`,
`list_project_ids`, `record_embedding_model`.

```python
class Repo:
    # -- registry [registry]
    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope: ...
        # raises ScopeResolutionFailed if no agent_registration row
    def create_project(self, name: str, retention_policy: Mapping[str, object] | None = None) -> ProjectId: ...
    def create_principal(self, kind: Literal["oidc_sub", "api_key"],
                         external_ref: str, key_hash: str | None) -> PrincipalId: ...
    def get_principal_by_external_ref(self, external_ref: str, *,
                                      kind: Literal["oidc_sub", "api_key"] | None = None
                                      ) -> PrincipalRow | None: ...   # C-29
    def list_project_ids(self) -> list[ProjectId]: ...          # sweeper iteration
    def record_embedding_model(self, model_id: str, model_version: str, dim: int, provider: str) -> None: ...
    def create_agent_type(self, project_id: ProjectId, name: str) -> AgentTypeId: ...
    def register_agent(self, project_id: ProjectId, principal_id: PrincipalId,
                       agent_type_id: AgentTypeId) -> None: ...  # raises DuplicateRegistration
    def create_agent_registration(self, project_id: ProjectId, agent_type_name: str,
                                  principal_kind: Literal["oidc_sub", "api_key"],
                                  external_ref: str, key_hash: str | None
                                  ) -> tuple[PrincipalId, AgentTypeId]: ...   # C-30, ONE transaction

    # -- memory (invariant 6 lives here)
    def insert_memory_item(self, project_id: ProjectId, item: NewMemoryItem,
                           scan_verdict: ScanVerdict) -> MemoryId: ...
        # order: validate_provenance(item.provenance) -> ProvenanceIncomplete;
        # scans.verify_verdict(scan_verdict, content_hash(item.content)) -> ScanVerdictForgery;
        # then INSERT with scan_verdict_id = verdict.verdict_id. No path skips either check.
    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> MemoryItemRow: ...
        # raises NotFound (uniform for absent / other-project)
    def list_memories(self, project_id: ProjectId, *, statuses: Sequence[Status] | None = None,
                      limit: int = 100) -> list[MemoryItemRow]: ...

    # -- trace index
    def upsert_trace_index(self, project_id: ProjectId, row: TraceIndexUpsert) -> None: ...
    def get_trace_index(self, project_id: ProjectId, run_id: RunId) -> TraceIndexRow: ...   # NotFound
    def list_runs(self, project_id: ProjectId, *, limit: int = 100) -> list[TraceIndexRow]: ...
    def find_runs_missing_sentinel(self, project_id: ProjectId,
                                   older_than: datetime) -> list[RunId]: ...
    def mark_run_incomplete(self, project_id: ProjectId, run_id: RunId) -> None: ...
    def append_trace_subject(self, project_id: ProjectId, run_id: RunId,
                             subject_tags: Sequence[str]) -> None: ...   # idempotent (PK upsert)

    # -- outcomes
    def insert_outcome_event(self, project_id: ProjectId, row: OutcomeEventInsert) -> bool: ...
        # ON CONFLICT (project_id, event_id) DO NOTHING; returns False on duplicate

    # -- telemetry primitives (Telemetry facade in telemetry.py wraps these)
    def insert_retrieval_event(self, project_id: ProjectId, row: RetrievalEventInsert) -> None: ...
    def insert_injection_rows(self, project_id: ProjectId, run_id: RunId,
                              rows: Sequence[InjectionRow]) -> None: ...
    def spend_add(self, project_id: ProjectId, day: date, worker: str, model_id: str,
                  tokens_in: int, tokens_out: int, cost_usd: float) -> None: ...   # UPSERT accumulate
    def spend_by_day(self, project_id: ProjectId, day: date) -> list[SpendRow]: ...

    # -- subject keys (crypto's storage; crypto NEVER executes SQL)
    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None: ...
    def insert_subject_key(self, project_id: ProjectId, subject_tag: str,
                           key_id: UUID, wrapped_kek: bytes) -> None: ...
    def destroy_subject_key(self, project_id: ProjectId, subject_tag: str) -> bool: ...
        # sets destroyed_at = clock.now(), overwrites wrapped_kek with b"" ; False if absent

    # -- review queue + config store (satisfies ConfigStorePort structurally)
    def insert_review_item(self, project_id: ProjectId, reason: str,
                           memory_id: MemoryId | None = None) -> None: ...
    def get_project_config(self, project_id: ProjectId) -> Mapping[str, object]: ...
    def get_agent_type_config(self, project_id: ProjectId, agent_type_id: AgentTypeId) -> Mapping[str, object]: ...
    def get_killswitch_overlay(self, project_id: ProjectId,
                               agent_type_id: AgentTypeId | None) -> Mapping[str, bool]: ...
    def set_project_config(self, project_id: ProjectId, key: str, value: object) -> None: ...

    # -- export
    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]: ...
        # yields {"table": ..., "row": {...}} dicts; api streams NDJSON from it
```

### §5.2 `stores/pg/rows.py` — row dataclasses (owner: repo)

All `@dataclass(frozen=True, slots=True)`; fields mirror the DDL columns with newtypes where
one exists. Cross-chunk consumers (ingest, harness, telemetry) import these, never invent dicts:

```python
class PrincipalRow:        principal_id: PrincipalId; kind: str; external_ref: str; key_hash: str | None; revoked_at: datetime | None
class MemoryItemRow:       id: MemoryId; project_id: ProjectId; scope_type: ScopeType; scope_id: UUID | None
                           mem_type: MemType; kind: str; lane: Lane; trust_tier: TrustTier; status: Status
                           content: str; content_hash: str; token_count: int; subject_tag: str | None
                           q_value: float; confidence: float; scored_use_count: int; strike_count: int
                           provenance: Provenance; scan_verdict_id: UUID; schema_version: int
                           created_at: datetime; status_changed_at: datetime | None
class TraceIndexUpsert:    run_id: RunId; agent_type_id: AgentTypeId; workflow_template_id: UUID | None
                           submitter_principal: PrincipalId; input_signature_hash: bytes
                           instrumentation_source: InstrumentationSource
                           # `arm` REMOVED (D-098): derived server-side from retrieval_event
                           path: Mapping[str, object] | None; started_at: datetime | None
                           ended_at: datetime | None; payload_ref: str | None
                           outcome_status: TraceOutcomeStatus
class TraceIndexRow:       (same fields, all concrete, plus project_id)
class OutcomeEventInsert:  event_id: UUID; run_id: RunId; principal_id: PrincipalId
                           adapter: AdapterClass; r: float; w_zero: bool
                           payload: Mapping[str, object]; occurred_at: datetime; arrived_at: datetime
class RetrievalEventInsert: run_id: RunId; outcome_code: OutcomeCode; latency_ms: int
                           embed_latency_ms: int | None; candidates_considered: int
                           top_score: float | None; arm: Arm
class InjectionRow:        memory_id: MemoryId; slot: Slot; score: float; tokens: int
class SubjectKeyRow:       subject_tag: str; key_id: UUID; wrapped_kek: bytes; created_at: datetime; destroyed_at: datetime | None
class SpendRow:            day: date; worker: str; model_id: str; tokens_in: int; tokens_out: int; cost_usd: float
```

- CHOICE (C-10): `outcome_event` gains no schema change for w=0 — `w_zero: bool` is carried in
  the row's `payload` jsonb under reserved key `"_w_zero"` by the repo (PLAN's DDL has no w
  column; w is never stored as a caller value, it is derivable from adapter class; the flag
  exists so Task 15's "implicit ⇒ w=0 flag recorded" is queryable).

### §5.3 `stores/pg/queue.py` — WorkQueue + topic constants (owner: queue)

Topic names are constants HERE and only here; producers/consumers import them:

```python
TOPIC_TRACE_EVENT: Final = "trace_event"
TOPIC_OUTCOME_EVENT: Final = "outcome_event"
TOPIC_MEMORY_PROPOSAL: Final = "memory_proposal"     # enqueued Phase 0, consumed Phase 4

@dataclass(frozen=True, slots=True)
class QueueItem:
    id: int; topic: str; project_id: ProjectId
    payload: Mapping[str, object]; priority: int; attempts: int

class WorkQueue:
    def __init__(self, pool: ConnectionPool, clock: Clock, cfg: QueueConfig) -> None: ...
    def enqueue(self, topic: str, project_id: ProjectId, payload: Mapping[str, object],
                priority: int = 100, available_at: datetime | None = None) -> int: ...
    def claim(self, topic: str, n: int) -> list[QueueItem]: ...
        # exactly the Task 12 SQL (FOR UPDATE SKIP LOCKED); BEFORE selecting, moves any
        # matching rows with attempts > max_attempts to dead_letter (C-11)
    def ack(self, item_id: int) -> None: ...             # DELETE
    def nack(self, item_id: int, backoff: timedelta) -> None: ...   # available_at += backoff, lease cleared
    def depth(self, topic: str) -> int: ...
    def oldest_age_s(self, topic: str) -> float | None: ...
    def dead_letter_count(self, topic: str) -> int: ...
```

Delivery is at-least-once; consumers are idempotent (trace writer on `(run_id, seq)`,
outcome intake on `event_id`). work_queue/dead_letter are unpartitioned → no GUC needed;
`project_id` rides in the row so consumers re-scope.

### §5.4 `stores/pg/telemetry.py` + `workers/spend.py` (owner: telemetry)

```python
class Telemetry:
    def __init__(self, repo: Repo, clock: Clock) -> None: ...
    def record_retrieval(self, project_id: ProjectId, run_id: RunId, *,
                         outcome_code: OutcomeCode, latency_ms: int,
                         embed_latency_ms: int | None, candidates_considered: int,
                         top_score: float | None, arm: Arm) -> None: ...
    def record_injections(self, project_id: ProjectId, run_id: RunId,
                          rows: Sequence[InjectionRow]) -> None: ...

@dataclass(frozen=True, slots=True)
class CapStatus:
    spent_today_usd: float; cap_usd: float; exceeded: bool

class SpendMeter:
    def __init__(self, repo: Repo, clock: Clock, cfg: SpendConfig) -> None: ...
    def add(self, project_id: ProjectId, worker: str, model_id: str,
            tokens_in: int, tokens_out: int, cost_usd: float) -> None: ...
    def check_cap(self, project_id: ProjectId) -> CapStatus: ...   # records only; Phase 3 enforces
```

### §5.5 `stores/pg/partitions.py` (owner: migrations)

```python
PARTITIONED_TABLES: Final[tuple[str, ...]]     # the 13 LIST-partitioned tables, one place
def partition_name(table: str, project_id: ProjectId) -> str:
    """f"{table}_p_{project_id.value.hex}" — fixed so tests can assert existence."""
def create_project_partitions(conn: psycopg.Connection, project_id: ProjectId) -> None: ...
def drop_project(conn: psycopg.Connection, project_id: ProjectId) -> None: ...
    # DETACH + DROP across all tables in the caller's single transaction
def ensure_schema_current(conn: psycopg.Connection) -> None: ...
```

These take a raw `conn` (they are DDL, run under migration/admin privileges, not the app role);
`api/admin.py` reaches them through `AppDeps.partitions` (§9.2), never via its own SQL.

---

## §6 `crypto/shred.py` + trace store (owner: crypto-tracestore)

### §6.1 Envelope format (C-12) — the trace payload binary/JSONL section format

An encrypted payload is UTF-8 JSONL: line 1 header, then one line per section.

```
{"v": 1, "fmt": "tb-env/1", "alg": "AES-256-GCM", "project_id": "<uuid>", "run_id": "<uuid>",
 "first_seq": 0, "last_seq": 17}
{"seq_from": 0, "seq_to": 4, "subject_tags": [], "nonce": "<b64>", "ct": "<b64>",
 "wraps": [{"tag": "__project__", "key_id": "<uuid>", "nonce": "<b64>", "share": "<b64>"}]}
{"seq_from": 5, "seq_to": 9, "subject_tags": ["user:alice", "third_party:acme"], ...}
```

- Plaintext of a section = the JSONL bytes of its trace events (one event per line, the exact
  wire `{"seq": n, "event": {...}}` objects).
- Section encryption: fresh 32-byte DEK, AES-256-GCM, 12-byte random nonce; AAD =
  `project_id ‖ run_id ‖ seq_from ‖ seq_to` (canonical string, C-12) so sections cannot be
  transplanted between runs.
- Key wrapping (C-13 — the multi-subject erasure decision): the DEK is split into N XOR shares,
  one per referenced subject tag (N=1, tag `"__project__"`, when untagged). Share_i is
  AES-256-GCM-encrypted under subject_i's KEK. Reconstruction needs ALL shares ⇒ destroying ANY
  referenced subject's KEK cryptographically tombstones the section. (PHASE-0 Task 10's "DEK
  wrapped under every referenced subject KEK" would leave multi-subject sections readable after
  one subject's erasure — that fails the erasure semantics, so shares it is; logged as C-13.)
- Subject KEKs: 32 random bytes, stored in `subject_key.wrapped_kek` AES-256-GCM-wrapped under
  the master key. Reserved tag `PROJECT_SUBJECT_TAG = "__project__"` is the per-project KEK row
  (C-14), provisioned at project creation by `/admin/projects`.

### §6.2 `crypto/shred.py` signatures

```python
PROJECT_SUBJECT_TAG: Final = "__project__"

class MasterKeyProvider(Protocol):
    def master_key(self) -> bytes: ...          # 32 bytes

class EnvMasterKeyProvider:
    """Reads base64 32-byte key from env TB_MASTER_KEY (C-15: env var, NOT TracebedSettings —
    key material stays out of the settings object so it never appears in dumps/repr).
    Raises MasterKeyMissing at construction if absent/malformed."""
    def __init__(self, env_var: str = "TB_MASTER_KEY") -> None: ...
    def master_key(self) -> bytes: ...

class SubjectKeyStore(Protocol):                # Repo satisfies structurally; fakes offline
    def get_subject_key(self, project_id: ProjectId, subject_tag: str) -> SubjectKeyRow | None: ...
    def insert_subject_key(self, project_id: ProjectId, subject_tag: str,
                           key_id: UUID, wrapped_kek: bytes) -> None: ...
    def destroy_subject_key(self, project_id: ProjectId, subject_tag: str) -> bool: ...

@dataclass(frozen=True, slots=True)
class PlainSection:
    seq_from: int; seq_to: int
    subject_tags: tuple[str, ...]               # () => project-KEK only
    lines: tuple[bytes, ...]                    # JSONL event lines

@dataclass(frozen=True, slots=True)
class TombstonedSection:                        # sentinel, NOT an exception — other sections
    seq_from: int; seq_to: int                  # of the same payload may still be readable
    subject_tags: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    header: Mapping[str, object]
    sections: tuple[Mapping[str, object], ...]
    def to_bytes(self) -> bytes: ...            # the §6.1 JSONL
    @classmethod
    def from_bytes(cls, raw: bytes) -> EncryptedPayload: ...

class SubjectKeyManager:
    def __init__(self, store: SubjectKeyStore, master: MasterKeyProvider, clock: Clock) -> None: ...
    def ensure_project_kek(self, project_id: ProjectId) -> None: ...
    def get_or_create_subject_kek(self, project_id: ProjectId, subject_tag: str) -> bytes: ...
    def destroy_subject(self, project_id: ProjectId, subject_tag: str) -> bool: ...
    def encrypt(self, project_id: ProjectId, run_id: RunId,
                sections: Sequence[PlainSection]) -> EncryptedPayload: ...
    def decrypt(self, project_id: ProjectId,
                payload: EncryptedPayload) -> list[PlainSection | TombstonedSection]: ...
```

### §6.3 `stores/tracestore/__init__.py` — TraceStorePort, PayloadRef

```python
@dataclass(frozen=True, slots=True)
class PayloadRef:
    driver: Literal["fs", "s3"]
    key: str                                    # driver-internal key, always embeds project_id
    def __str__(self) -> str: ...               # "fs://{key}" | "s3://{bucket}/{key}" — what
    @classmethod                                #   trace_index.payload_ref stores
    def parse(cls, ref: str) -> PayloadRef: ...

class TraceStorePort(Protocol):
    def put(self, project_id: ProjectId, run_id: RunId, first_seq: int,
            payload: bytes) -> PayloadRef: ...
    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes: ...    # raises NotFound;
        # ALSO raises NotFound if ref.key does not start with this project's prefix (leak probe)
    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool: ...
    def delete_project(self, project_id: ProjectId) -> int: ...            # objects removed
```

- CHOICE (C-16): the port speaks `bytes`, not `EncryptedPayload` (deviation from Task 11's
  wording). Conversion via `EncryptedPayload.to_bytes()/from_bytes()` happens in
  `ingest.trace_writer`. Why: keeps `tracebed.crypto` out of the `stores.*` import graph —
  `purity_check.py` forbids `tracebed.crypto` from hotpath, and hotpath may import `stores.*`.
- Key layouts (fixed): fs `{root}/{project_id}/{run_id}/{first_seq:08d}.tbz`;
  s3 `tb/{project_id}/{run_id}/{first_seq:08d}` in `cfg.tracestore.bucket`. S3 driver is
  hand-rolled sigv4 over httpx (no boto3 — keeps D-036's dependency set closed).

---

## §7 `stores/valkey/keys.py` — the only `tb:` site (owner: harness)

```python
def tool_cache_key(project_id: ProjectId, *, tool_id: str, tool_version: str,
                   auth_context_fingerprint: str, args: Mapping[str, object]) -> str:
    """tb:{project_id}:tc:{sha256_hex(RS.join([str(project_id), tool_id, tool_version,
    auth_context_fingerprint, canonical_args(args).decode()]))} where RS = "\\x1f"
    (C-17: unit-separator-joined, canonical_args from §2)."""

def working_memory_key(project_id: ProjectId, run_id: RunId, key: str) -> str:
    """tb:{project_id}:wm:{run_id}:{key}"""

def static_prefix_key(project_id: ProjectId, agent_type_id: AgentTypeId, prefix_version: int) -> str:
    """tb:{project_id}:px:{agent_type_id}:{prefix_version}"""

def project_key_pattern(project_id: ProjectId) -> str:
    """tb:{project_id}:* — O(1)-flush scan pattern; also what leak probe 6 sweeps."""
```

---

## §8 `adapters/ports.py` — every cross-chunk Protocol (owner: domain-events-scan)

Protocols ONLY — zero implementations, zero I/O, imports from `domain` + `stores.tracestore`
types only. Concrete classes satisfy these structurally (no inheritance required). This file
is what lets api-auth, ingest, and sdk test offline against fakes.

```python
class PrincipalPort(Protocol):
    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal: ...
        # raises AuthenticationFailed  (Principal defined in adapters/identity.py, §9.1;
        # re-exported here once api-auth lands — ports.py declares it as a Protocol member type
        # via TYPE_CHECKING import)

class ProjectResolverPort(Protocol):
    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope: ...

class QueueProducerPort(Protocol):              # api routes depend on this, not on WorkQueue
    def enqueue(self, topic: str, project_id: ProjectId, payload: Mapping[str, object],
                priority: int = 100, available_at: datetime | None = None) -> int: ...

class QueueConsumerPort(Protocol):              # ingest depends on this
    def claim(self, topic: str, n: int) -> list[QueueItem]: ...
    def ack(self, item_id: int) -> None: ...
    def nack(self, item_id: int, backoff: timedelta) -> None: ...

class TelemetryPort(Protocol):
    def record_retrieval(self, project_id: ProjectId, run_id: RunId, *, outcome_code: OutcomeCode,
                         latency_ms: int, embed_latency_ms: int | None,
                         candidates_considered: int, top_score: float | None, arm: Arm) -> None: ...

class FeedbackPort(Protocol):                   # Phase 3 adapters implement; declared now
    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent: ...

class InvalidationPort(Protocol):               # Phase 2; declared now
    def poll(self) -> Sequence[Mapping[str, object]]: ...

class LLMProviderPort(Protocol):                # Phase 3 workers; declared now
    def complete(self, *, model: str, prompt: str, temperature: float,
                 max_tokens: int) -> str: ...

class EmbeddingPort(Protocol):                  # Phase 1; declared now
    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]: ...
    @property
    def model_id(self) -> str: ...
    @property
    def model_version(self) -> str: ...

class AuditSinkPort(Protocol):
    def emit(self, event: Mapping[str, object]) -> None: ...

TraceStorePort  # re-exported: from tracebed.stores.tracestore import TraceStorePort
SubjectKeyStorePort = SubjectKeyStore           # re-exported from crypto? NO — see note
```

- CHOICE (C-18): `SubjectKeyStore` and `ConfigStorePort` stay defined next to their consumers
  (`crypto/shred.py`, `domain/config.py`) because `ports.py` must not import `crypto` (purity
  graph) — `ports.py` re-exports only `TraceStorePort`. The final symbol list of `ports.py`:
  PrincipalPort, ProjectResolverPort, QueueProducerPort, QueueConsumerPort, TelemetryPort,
  FeedbackPort, InvalidationPort, LLMProviderPort, EmbeddingPort, AuditSinkPort, TraceStorePort.

---

## §9 API (owner: api-auth)

### §9.1 `adapters/identity.py`

```python
@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: PrincipalId
    kind: Literal["oidc_sub", "api_key"]
    external_ref: str

class OidcJwksVerifier:
    def __init__(self, jwks_url: str, issuer: str, *, audience: str = "tracebed",
                 http: httpx.Client | None = None) -> None: ...
    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal: ...
        # RS256 via PyJWT + PyJWKClient; iss/aud checked; principal looked up by
        # kind="oidc_sub", external_ref=token["sub"]; unknown sub -> AuthenticationFailed

class ApiKeyVerifier:
    def __init__(self, principals: PrincipalLookup) -> None: ...   # Protocol: get_principal_by_external_ref
    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal: ...

class ChainVerifier:
    """Bearer -> OIDC (if configured); X-API-Key -> ApiKeyVerifier (if api_key_mode).
    Neither present/valid -> AuthenticationFailed. Satisfies PrincipalPort."""
```

API-key format (C-19): `tb_sk_<key_id>.<secret>` where `key_id` is a UUID hex and `secret` is
43 chars of `secrets.token_urlsafe(32)`. Storage: `principal.kind='api_key'`,
`external_ref=key_id`, `key_hash=sha256_hex(secret)`. Verification: parse key → fetch by
external_ref → `hmac.compare_digest(sha256_hex(presented_secret), key_hash)` → check
`revoked_at IS NULL`. Constant-time compare on the hash, lookup by public id.

Admin bootstrap (C-02/C-20): registry-creating routes (`POST /admin/projects`,
`POST /admin/agents/register`) authenticate with the static admin key from env
`TB_ADMIN_KEY` (header `X-Admin-Key`, compare_digest against its sha256). They cannot use
principal auth because no registration exists yet (chicken-and-egg). Project-scoped admin
reads (`GET /admin/memory/{id}`, `GET /export/project`) use normal principal auth + scope —
which is why leak probe 3 gets a 404, not cross-project data.

### §9.2 `api/deps.py`

```python
@dataclass(slots=True)
class AppDeps:
    """Everything create_app needs, typed as Protocols so api tests run offline with fakes."""
    verifier: PrincipalPort
    resolver: ProjectResolverPort               # Repo satisfies
    queue: QueueProducerPort                    # WorkQueue satisfies
    telemetry: TelemetryPort                    # Telemetry satisfies
    memory_reader: MemoryReaderPort             # get_memory_by_id — Repo satisfies (Protocol here)
    exporter: ExportPort                        # iter_export_rows — Repo satisfies (Protocol here)
    admin: AdminPort                            # create_project/create_agent_type/register_agent/
                                                #   create_principal — Repo satisfies (Protocol here)
    partitions: PartitionsPort                  # create_project_partitions bound to a conn factory
    keys: SubjectKeyProvisionerPort             # ensure_project_kek — SubjectKeyManager satisfies
    clock: Clock

def get_principal(request: Request) -> Principal: ...       # -> 401 on AuthenticationFailed
def get_scope(principal: Principal = Depends(get_principal)) -> ProjectScope: ...  # -> 403
def require_admin_key(request: Request) -> None: ...        # -> 401; C-20 bootstrap auth
```

(`MemoryReaderPort`, `ExportPort`, `AdminPort`, `PartitionsPort`, `SubjectKeyProvisionerPort`
are small Protocols DECLARED IN `api/deps.py` — api-auth owns them; they exist purely so the
API is testable offline. They mirror Repo/partitions/SubjectKeyManager signatures exactly.)

```python
# api/main.py
def create_app(settings: TracebedSettings, deps: AppDeps) -> FastAPI: ...
def run() -> None: ...    # console entry point: builds real deps from settings, uvicorn on api.port
```

### §9.3 Routes — paths, codes, bodies (per PLAN §3; stub semantics per Task 16)

| Route | Auth | Status | Notes |
|---|---|---|---|
| `GET /healthz` | none | 200 | `{"status":"ok"}` — compose/liveness only |
| `POST /v1/retrieve` | principal | 200 | Phase 0 stub: mint `run_id` (uuid7), arm=`memory_on` (holdout wiring is Phase 1), outcome_code=`empty_result`, `context_block=empty_context_block()`, then `telemetry.record_retrieval` with measured latency. Response = `RetrieveResult` |
| `POST /v1/trace` | principal | 202 | body `TraceIn`; enqueue only; response `{"status":"accepted"}` |
| `POST /v1/trace/batch` | principal | 202 | C-21: `{"events": [TraceIn, ...]}` max 500 — the SDK flusher's endpoint; single-event route kept per PLAN |
| `POST /v1/feedback` | principal | 202 | body `FeedbackIn`; enqueue only; extra fields (e.g. `weight`) → 422 |
| `POST /v1/propose_memory` | principal | 202 | validated, enqueued to `TOPIC_MEMORY_PROPOSAL`; no Phase 0 consumer (server activates Phase 4) |
| `POST /admin/projects` | admin key | 201 | `{"name": str, "retention_policy"?: obj}` → creates registry row, partitions, project KEK; returns `{"project_id": uuid}` |
| `POST /admin/agents/register` | admin key | 201 | `{"project_id": uuid, "agent_type": str, "principal": {"kind": "api_key"} \| {"kind": "oidc_sub", "sub": str}}` → creates agent_type if new, principal, registration; api_key kind returns the ONE-TIME plaintext key: `{"principal_id", "agent_type_id", "api_key"?}`. (project_id appears here because the ADMIN names the project being provisioned — this is the registry write path, not a data route; data routes never accept it.) |
| `GET /admin/memory/{memory_id}` | principal | 200/404 | scope-derived project; uniform 404 body |
| `GET /export/project` | principal | 200 | `application/x-ndjson` stream of `iter_export_rows(scope.project_id)` |

Wire models (api/routes_v1.py; all `extra="forbid"`):

```python
class RunCtxIn(BaseModel):     # PLAN §3 retrieve run_ctx
    query_text: str; workflow_template: str | None = None; user_ref: str | None = None
    session_id: str | None = None; prefetch_for: str | None = None
class RetrieveIn(BaseModel):   agent_type: str; run_ctx: RunCtxIn
class TraceIn(BaseModel):      run_id: UUID; seq: int; event: TraceEvent
class TraceBatchIn(BaseModel): events: list[TraceIn]        # max_length=500
class FeedbackIn(BaseModel):   run_id: UUID; event: FeedbackEvent
class ProposeIn(BaseModel):    run_id: UUID; proposal: MemoryProposal
```

### §9.4 Error → HTTP mapping (one exception handler in api/main.py)

| Exception | HTTP | Body |
|---|---|---|
| `AuthenticationFailed` | 401 | `{"detail": "authentication failed"}` |
| `ScopeResolutionFailed` | 403 | `{"detail": "no project registration"}` |
| `NotFound` | 404 | `{"detail": "not found"}` — EXACTLY this, both for absent and other-project (leak probe 2) |
| `DuplicateRegistration` | 409 | `{"detail": "principal already registered"}` |
| Pydantic validation | 422 | FastAPI default |
| any other `TracebedError` | 500 | `{"detail": "internal error"}` — no class names, no messages leak |

### §9.5 Queue payload envelopes (C-22) — what api enqueues, what ingest consumes

The queue payload is JSON (jsonb). Exact shapes — ingest parses these, nothing else:

```python
# TOPIC_TRACE_EVENT — one per event (batch route enqueues N of these)
{"project_id": "<uuid>", "principal_id": "<uuid>", "agent_type_id": "<uuid>",
 "run_id": "<uuid>", "seq": 3, "event": {"type": "...", "ts": "...", "payload": {...}}}

# TOPIC_OUTCOME_EVENT
{"project_id": "<uuid>", "principal_id": "<uuid>", "run_id": "<uuid>",
 "event": {"adapter": "...", "outcome": "positive|negative", "payload": {...},
           "event_id": "<uuid>", "occurred_at": "<iso8601>|null"}}

# TOPIC_MEMORY_PROPOSAL
{"project_id": "<uuid>", "principal_id": "<uuid>", "run_id": "<uuid>",
 "proposal": {"mem_type": "...", "content": "...", "subject_tag": null, "claimed_scope": "..."}}
```

`project_id`/`principal_id`/`agent_type_id` come from `ProjectScope` server-side — the caller's
body never contained them. This is how the authenticated principal reaches
`trace_index.submitter_principal` and `outcome_event.principal_id` (Task 14/15).

---

## §10 SDK (owner: sdk)

`sdk/client.py` implements EXACTLY the PHASE-0 Task 13 surface (already exact — reproduced
there; do not restyle it). Binding clarifications:

- Imports: `tracebed.domain.*` and `httpx` ONLY. Never `stores`, `api`, `ingest`.
- `retrieve()` wire mapping: kwargs `session_id`/`prefetch_for` are folded into the
  `run_ctx` object of `RetrieveIn`; `RunContext.tool_manifest` is NOT sent to retrieve (it
  rides on the `run_start` trace event payload, C-05).
- On ANY transport error/timeout/non-200: return
  `RetrieveResult(run_id=mint_run_id().value, run_id_origin="sdk", arm=Arm.MEMORY_ON,
  outcome_code=OutcomeCode.STORE_ERROR, context_block=empty_context_block())` — never raise.
- The client remembers `run_id -> arm` from each retrieve result (bounded LRU, 4096 entries);
  when a `run_start` event for a known run is enqueued, it stamps `payload["arm"]` (C-05).
- `sdk/buffer.py`:

```python
@dataclass(frozen=True, slots=True)
class FlushReport:
    sent: int
    dropped: int                                # cumulative drops since last flush() return

class RingBuffer:
    def __init__(self, capacity: int) -> None: ...
    def append(self, run_id: RunId, kind: Literal["trace", "feedback", "proposal"],
               body: Mapping[str, object]) -> int: ...
        # assigns seq for kind="trace": per-run monotonic counter starting at 0, held in the
        # buffer (C-23); drop-oldest at capacity, increments dropped_total
    def drain(self, max_items: int) -> list[BufferedItem]: ...
    @property
    def dropped_total(self) -> int: ...
```

- Background flusher: daemon thread, wakes every `flush_interval_s`, drains up to 500, POSTs
  `/v1/trace/batch` (trace) and `/v1/feedback` / `/v1/propose_memory` (singles). All exceptions
  swallowed and counted (`_flush_errors`); `flush(timeout_s)` forces a synchronous drain and
  returns `FlushReport`. `run_end(status)` appends the `run_end` event (payload
  `{"status": status}`, final seq) then calls `flush()`.
- ≤1ms p99: `trace()`/`feedback()` do dict-build + ring append only — no serialization, no
  locks held across I/O, no HTTP on the caller thread, ever.

---

## §11 Ingest (owner: ingest)

```python
# ingest/trace_writer.py
class TraceWriter:
    """Consumes TOPIC_TRACE_EVENT. PHASE-0 Task 14. All deps are Protocols/fakes-friendly."""
    def __init__(self, queue: QueueConsumerPort, repo: Repo, store: TraceStorePort,
                 keys: SubjectKeyManager, clock: Clock, settings: TracebedSettings) -> None: ...
    def run_once(self, max_batch: int | None = None) -> int:
        """Claim -> group by (project_id, run_id) -> order by seq, drop exact (run_id, seq)
        duplicates (idempotency) -> build PlainSections (section boundary: consecutive events
        with the same subject_tags set, C-24) -> keys.encrypt -> EncryptedPayload.to_bytes ->
        store.put -> repo.tx(project_id): upsert_trace_index + append_trace_subject.
        run_start populates started_at, input_signature_hash (§3.8 from C-05 payload keys,
        ABSENT_SIGNATURE if the run never had a run_start), arm, submitter_principal (from the
        envelope), instrumentation_source=SDK. run_end sets ended_at + outcome_status.
        Returns events processed; ack on success, nack(backoff=lease) on error."""
    def sweep_incomplete(self) -> int:
        """For each project (repo.list_project_ids): find_runs_missing_sentinel(older_than =
        clock.now() - 2 * session.idle_ttl_min) -> mark_run_incomplete. Sequence-gap detection:
        a run whose stored seq set has holes at sentinel time is also marked incomplete."""

# ingest/outcome_intake.py
class OutcomeIntake:
    """Consumes TOPIC_OUTCOME_EVENT. PHASE-0 Task 15."""
    def __init__(self, queue: QueueConsumerPort, repo: Repo, clock: Clock,
                 settings: TracebedSettings) -> None: ...
    def run_once(self, max_batch: int | None = None) -> int:
        """Validate adapter; r = 1.0 if outcome=="positive" else 0.0; w derived from
        scoring.adapter_weights (server-side ONLY); implicit -> payload["_w_zero"]=True (C-10);
        insert_outcome_event (dedup on event_id); NO join to trace_index required or attempted
        (attach-by-run_id is logical). Zero Q-mutation code exists in Phase 0 at all —
        which is itself the invariant-8 guarantee this phase can make."""
```

Multi-payload runs (C-25): each `run_once` batch for a run produces ONE object put with that
batch's `first_seq`; `trace_index.payload_ref` keeps the ref of the FIRST put (lowest
first_seq); later refs are recorded in `trace_index.path` under key `"payload_refs": [...]`
(jsonb list, append). Phase 0's gate scenario (one run, one batch) exercises one object; the
schema survives streaming.

---

## §12 Offline-first testing rule

There is no Docker/Postgres/Valkey/S3 on the build machine. Therefore:

- Pure logic (state machine, signatures, canonical, provenance validation, scans, crypto with
  fake stores, SDK with dead server, config resolution with fake ConfigStore, ingest with fake
  queue/repo/store, api with fake AppDeps) is tested WITHOUT any service — these tests carry
  `@pytest.mark.phase0` only and MUST pass on this machine.
- DB/Valkey/S3-touching tests carry `@pytest.mark.phase0` AND `@pytest.mark.integration` and
  use the §13.1 fixtures, which `pytest.skip` at setup when `TB_STORAGE__PG_DSN` (etc.) is
  unset or unreachable. Import of psycopg/valkey at module top-level is fine; CONNECTING at
  collection time is forbidden.

## §13 TEST OWNERSHIP

### §13.1 `tests/phase0/conftest.py` (owner: harness) — the ONLY conftest; fixtures by name

```python
fake_clock          # FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
pg_dsn              # str; skips: env TB_STORAGE__PG_DSN unset OR connect fails (1s timeout)
pg_pool             # ConnectionPool from pg_dsn; migrations applied once per session
repo                # Repo(pg_pool, fake_clock)
work_queue          # WorkQueue(pg_pool, fake_clock, QueueConfig())
valkey_url          # str; skips when TB_STORAGE__VALKEY_URL unset/unreachable
s3_config           # skips when TB_S3_ENDPOINT unset/unreachable
settings            # TracebedSettings with in-memory-safe defaults (pg_dsn="postgresql://unused",
                    #   model_version="test") — for pure tests; never used to connect
two_projects        # (ProjectScope, ProjectScope) for projects A and B with registered
                    #   principals + partitions; integration-only; THE leak-suite fixture
```

Other chunks USE these fixtures; only harness edits this file. Chunk-local fakes (FakeRepo,
FakeQueue, FakeStore, FakeVerifier...) live inside the chunk's own test modules — duplication
of fakes across chunks is accepted; a shared fakes module would be a merge collision.

### §13.2 Test-file map — two coders never write the same file

RECONCILED AT INTEGRATION (C-28). The table below is the tree as built. Ten rows in the
original map named files that were never created — in every case the chunk merged the
subject matter into a differently-named module (for example `test_repo.py` /
`test_repo_exports.py` became `test_repo_scoping.py` + `test_repo_provenance.py` +
`test_repo_isolation_offline.py`, and `test_tracestore_fs.py` + `test_tracestore_s3.py`
became one `test_tracestore.py`). Keeping a map that names files nobody wrote is worse than
having no map, because a future reader cannot tell "not written" from "written elsewhere".

| Test file | Chunk | Proves |
|---|---|---|
| `tests/conftest.py` | domain-config | `fake_clock`, `settings`, `tracestore_root`, and THE `pg` reachability probe |
| `tests/phase0/conftest.py` | harness | the §13.1 live-stack fixtures; every one skips, never errors |
| `tests/phase0/test_config.py` | domain-config | defaults w/ 2 env vars; env override; unknown key rejected; ConfigResolver precedence |
| `tests/phase0/test_clock.py` | domain-config | Clock protocol; FakeClock determinism; SystemClock is the one wall-clock site |
| `tests/phase0/test_ids.py` | domain-events-scan | uuid7 monotonicity; TypedId newtype separation |
| `tests/phase0/test_enums_events.py` | domain-events-scan | enum wire values; event union discriminator; extra="forbid" (weight→error); naive-ts rejection; the error hierarchy |
| `tests/phase0/test_canonical.py` | domain-events-scan | canonical_json stability; content_hash NFC |
| `tests/phase0/test_signatures.py` | domain-events-scan | simhash properties; 40-byte layout; same_cluster; feature-order independence |
| `tests/phase0/test_scan_verdict_type.py` | domain-events-scan | ScanVerdict constructor guard raises from every other module (Task 3) |
| `tests/phase0/test_state_machine.py` | domain-state-machine | full table; deficient evidence per row; exhaustive Status×Status illegal rejection; proposal-never-skips; Sybil |
| `tests/phase0/test_migrations.py` [integration] | migrations | apply+rollback; extensions; UNIQUE(principal_id); NULL scan_verdict_id fails |
| `tests/phase0/test_partitions.py` [integration] | migrations | two projects; drop_project one-transaction; RLS zero-rows w/o GUC |
| `tests/phase0/test_repo_scoping.py` [integration] | repo | NotFound cross-project == absent; the §5.1 scope-less allowlist grep-test |
| `tests/phase0/test_repo_provenance.py` [integration] | repo | invariant 6 against a real DB — a rejected insert reaches no row |
| `tests/phase0/test_repo_isolation_offline.py` | repo | every public builder drives a fake connection; GUC is the first statement outside the allowlist |
| `tests/phase0/test_queue.py` [integration] | queue | 2 consumers ×1,000 rows zero double-claims; lease expiry redelivery; dead-letter; priority order |
| `tests/phase0/test_scans.py` | scans | corpus 100% strong-signal rejection; benign passes; verdict()/verify_verdict; forged verdict fails |
| `tests/phase0/test_tier_a_zero_passthrough.py` | scans | no str free-text field (introspection); rendered note shares no ≥8-byte substring with error-body fixtures |
| `tests/phase0/test_crypto_shred.py` | crypto-tracestore | offline w/ fake store: A/B sections; destroy(A) → Tombstoned, B readable, bytes unchanged; XOR-share multi-subject erasure |
| `tests/phase0/test_tracestore.py` (+[integration] S3 half) | crypto-tracestore | tmpdir round-trip; key embeds project_id; cross-project ref → NotFound; sigv4 vectors; SeaweedFS round-trip |
| `tests/phase0/test_auth.py` | api-auth | 401 paths; API-key verify; OIDC against generated JWKS; alg-confusion; JWKS cooldown; admin-key gate; `_RepoPrincipalLookup` |
| `tests/phase0/test_api_scope.py` | api-auth | offline TestClient + fake AppDeps: retrieve stub shape; 202s; project_id in body → 422; weight → 422; uniform 404; export scoping |
| `tests/phase0/test_admin_routes.py` | api-auth | the two auth planes; principal auth cannot substitute for the admin key; registration atomicity (C-30) |
| `tests/phase0/test_sdk_buffer.py` | sdk | seq monotonic per run; drop-oldest + counter |
| `tests/phase0/test_sdk_client.py` | sdk | dead-server: trace/feedback ≤1ms p99, zero raises; retrieve degraded result; run_end flushes; wire shapes match §9.3's models |
| `tests/phase0/test_trace_writer.py` | ingest | offline fakes: full run → index+payload+subjects; dup seq idempotent; sweeper → incomplete; sig-hash reorder-stable; owner stability; run lock (C-32) |
| `tests/phase0/test_outcome_intake.py` | ingest | offline fakes: r/w derivation; event_id replay → one insert; implicit → _w_zero; T+2-day attach joins by run_id |
| `tests/phase0/test_ingest_runner.py` | ingest | dispatch isolation; sweep cadence is wall-clock, not poll-count; graceful shutdown |
| `tests/phase0/test_telemetry.py` [integration] | telemetry | retrieval_event/injection rows land under caller's project; TelemetryPort signature conformance |
| `tests/phase0/test_spend.py` | telemetry | accumulation by day; UTC bucketing from the injected Clock; deltas that would disable the cap are refused |
| `tests/phase0/test_valkey_keys.py` | harness | key formats; injectivity under the 0x1F join; distinct projects → disjoint key sets; pattern shape (pure) |
| `tests/phase0/test_valkey_client.py` | harness | offline via an injected `ValkeyCommands`: TTL enforcement, per-project isolation, delete_project batching |
| `tests/phase0/test_integration_seams.py` | integrator | the cross-chunk assertions no single chunk could make (invariant 4 end to end, ScanVerdict reachability, hard rule 4, the §13.1 fixture surface) |
| `harness/leak_suite/test_leaks.py` [integration] | harness | the seven probes (Task 17) |

NOT BUILT: `tests/phase0/test_gate_smoke.py` (harness). `harness/phase0_gate.py` — the runner
whose verdict *is* the Phase 0 gate — has no automated test of its own. Its verdict logic is
the single most correctness-critical thing in the phase (a false PASS is worse than a FAIL),
and it is currently verified only by reading it and by running it. Carried into Phase 1.

The three CI scripts already ship self-tests; harness wires them into `phase0_gate.py`,
which must run everything above plus license/raw-sql lints and emit `gate_report_phase0.md`
with per-assertion pass/fail/skip (skips listed loudly — a skipped integration test is visible
in the report, never silent).

## §14 DO-NOT LISTS (the PHASE-0 ordering hazards, per chunk)

Every chunk: do NOT modify [frozen] files, files owned by another chunk, or this contract.
Do NOT add dependencies beyond pyproject.toml (D-036) — needing one is a contract_gap.
Do NOT call `datetime.now()`/`time.time()` outside SystemClock (monotonic latency measurement
via `clock.monotonic_ms()`).

- **domain-config**: no I/O in config.py beyond pydantic-settings env reading; ConfigResolver
  takes a store Protocol — do NOT import stores/pg. errors.py imports stdlib only.
- **domain-events-scan**: domain stays pure — no psycopg, no httpx, no fastapi imports
  anywhere under `domain/`. ports.py: Protocols only, no crypto import (C-18).
- **domain-state-machine**: the machine never reads config, DB, or clocks — everything arrives
  in TransitionEvidence/TransitionLimits. Do NOT add an admin/bypass path (invariant 7);
  do NOT make proposal-skip refusal configurable.
- **migrations**: RLS `ENABLE` + `FORCE` on every partitioned table, policy exactly
  `USING (project_id = current_setting('tracebed.project_id')::uuid)`; app role not owner, no
  BYPASSRLS. `memory_item.scan_verdict_id` NOT NULL from the first migration — the scan module
  precedes every write path (RT-03) and the schema must make skipping it impossible.
- **repo**: no builder without `project_id` beyond the §5.1 registry allowlist; every
  partitioned-table transaction starts with the §5.0 set_config statement; do NOT catch
  ProvenanceIncomplete/ScanVerdictForgery internally; do NOT distinguish "not yours" from
  "doesn't exist" in NotFound.
- **queue**: at-least-once only — do NOT promise exactly-once; do NOT add topics beyond the
  three constants; do NOT touch partitioned tables (work_queue/dead_letter only).
- **scans**: scan() stays pure — no repo import, no I/O (review-queue persistence is the
  caller's); TierANote gets NO free-text parameter, ever (D-019); ScanVerdict minting only via
  ScanResult.verdict().
- **crypto-tracestore**: crypto executes NO SQL (SubjectKeyStore protocol only); the envelope
  lands BEFORE the first trace byte is written — tracestore drivers accept opaque bytes and
  must not offer a plaintext path; no MinIO SDK, no boto3 (C-16).
- **api-auth**: no route reads project_id/weights/arm from a request (the one registry
  exception is §9.3's admin register route); routes 202 + enqueue — do NOT write
  trace/outcome rows synchronously; registries + auth precede all routes — no unauthenticated
  route except /healthz.
- **sdk**: never raises from trace/feedback/propose/retrieve; no imports beyond domain +
  httpx; no server-side types (rows.py etc.); do NOT compute input_signature_hash client-side
  (server derives it — the SDK just ships the C-05 payload keys).
- **ingest**: consumers idempotent (claims may replay); encrypt BEFORE put — a plaintext
  payload never reaches TraceStorePort; principal comes from the queue envelope (server-side),
  never from event payloads.
- **telemetry**: writers only — no reads of other projects, no aggregation across projects
  (spend org-rollup is Phase-later and billing-only, D-037).
- **harness**: leak suite asserts on EVERYTHING (bodies, error shapes, exports, key strings);
  do NOT weaken a probe to make it pass — a red probe is a finding, not a test bug; keys.py is
  the only `tb:` site (the lint enforces it — do not construct keys inline even in tests).

## §15 CHOICES MADE HERE (not in PLAN.md / PHASE-0.md) — mirror to DECISIONS.md at merge

- **C-01** Canonical JSON: `sort_keys=True`, `(",", ":")`, `ensure_ascii=False`, `allow_nan=False`,
  UTF-8; `content_hash` = sha256 hex over NFC-normalised text. One owner: `domain/canonical.py`.
- **C-02** `AuthConfig.admin_key_env` (default `"TB_ADMIN_KEY"`) added — the only config field
  beyond Task 2's listing; bootstrap admin auth for registry-creating routes.
- **C-03** Config overrides are dotted-path keys; deployment-level sections not overridable;
  violations raise ConfigError at effective() time.
- **C-04** CONFLICT resolved: `seq` lives on the wire envelope, not on TraceEvent (PLAN §3 wins
  over PHASE-0 Task 3's wording).
- **C-05** Reserved trace-payload keys: `subject_tags` (state_note/artifact_ref);
  `query_text`/`workflow_template`/`tool_manifest`/`arm` (run_start); `status` (run_end).
- **C-06** ScanVerdict forgery resistance: caller-module frame guard in domain/scan.py +
  process-local HMAC key in core/scans/_authority.py; repo verifies via
  `core.scans.verify_verdict(verdict, content_hash)`. Verdicts are process-lifetime only.
- **C-07** input_signature_hash = sha256(canonical_json({agent_type, workflow_template,
  sorted tool_manifest})) ‖ simhash64(query_text head, 512 chars) = 40 bytes;
  `ABSENT_SIGNATURE = bytes(40)` for runs with no run_start.
- **C-08** "Any non-terminal → tombstoned" materialised as: every status except TOMBSTONED has
  a tombstone edge (erasure reaches retired/superseded/archived too).
- **C-09** RLS GUC set via `SELECT set_config('tracebed.project_id', %s, true)` as the first
  statement of every partitioned-table transaction (SET LOCAL cannot bind parameters); Repo
  owns all transactions; `Repo.tx(project_id)` is the only multi-statement composition tool.
- **C-10** w=0 signal recorded as `payload["_w_zero"] = true` on outcome_event (no schema
  column; w is derivable, never stored as caller data).
- **C-11** Queue exhaustion: `claim()` moves attempts-exhausted rows to dead_letter before
  selecting (no separate reaper in Phase 0).
- **C-12** Trace envelope: JSONL (header line + section lines), AES-256-GCM per section, AAD
  binds project_id/run_id/seq-range.
- **C-13** Multi-subject sections use XOR DEK shares (one per subject KEK) so destroying ANY
  referenced subject's KEK cryptographically tombstones the section — deviation from Task 10's
  "wrapped under every KEK" wording, which would leave multi-subject sections readable after a
  single-subject erasure.
- **C-14** Reserved subject tag `"__project__"` is the per-project KEK row in subject_key;
  provisioned by POST /admin/projects.
- **C-15** Master key from env `TB_MASTER_KEY` (base64, 32 bytes) via EnvMasterKeyProvider —
  deliberately outside TracebedSettings so key material never sits in the settings object.
- **C-16** TraceStorePort speaks bytes (not EncryptedPayload) to keep `tracebed.crypto` out of
  the stores import graph (purity gate); S3 driver is httpx+sigv4, no boto3.
- **C-17** Tool-cache hash input: 0x1F-joined (project_id, tool_id, tool_version,
  auth_context_fingerprint, canonical_args) → sha256 hex.
- **C-18** ports.py holds 11 named Protocols; SubjectKeyStore and ConfigStorePort stay beside
  their consumers (crypto, config) to keep ports.py import-clean.
- **C-19** API-key format `tb_sk_<key_id>.<secret>`; store sha256(secret) keyed by public
  key_id in principal.external_ref; compare_digest verification.
- **C-20** Registry-creating admin routes authenticate with the static TB_ADMIN_KEY
  (X-Admin-Key header); project-scoped admin reads use principal auth + derived scope.
  The register route's body names project_id — registry provisioning, not a data route.
- **C-21** `POST /v1/trace/batch` (max 500) added as the SDK flusher endpoint; single-event
  route kept exactly per PLAN.
- **C-22** Queue payload envelopes fixed (§9.5): scope ids injected server-side from
  ProjectScope; ingest reads only these shapes.
- **C-23** Per-run seq counters live in the SDK ring buffer, start at 0, monotonic per run,
  assigned at enqueue.
- **C-24** Crypto section boundaries: consecutive events sharing an identical subject_tags set
  form one section.
- **C-25** Multi-batch runs: payload_ref keeps the first object's ref; subsequent refs append
  to trace_index.path["payload_refs"].
- **C-26** Phase 0 retrieve stub always assigns arm="memory_on" (holdout hashing lands Phase 1);
  RetrieveResult gains `run_id_origin: "server"|"sdk"` making D-018's origin flag explicit on
  the wire.

### Made at integration (C-27 … C-35)

Six chunks were built in parallel against this document without seeing each other's files.
Everything below is a seam the contract did not resolve, or a place where two conforming
modules still disagreed. The originals are preserved above; these amend them.

- **C-27** `tests/phase0/conftest.py` rebuilt against the real constructors. As merged,
  `pg_pool` built a `ScopedPool` that `stores/pg/pool.py` does not define, `work_queue` passed
  `WorkQueue` two of its three required arguments, and `two_projects` — §13.1's "THE leak-suite
  fixture" — did not exist. All three were invisible because `tests/conftest.py::pg` skips
  before any fixture body runs on a machine with no Postgres; all three would have turned five
  test modules into setup ERRORs the moment a database appeared, which reads exactly like a
  real isolation failure. `pg_pool` is now `create_pool(dsn)` with migrations applied once per
  session per DSN; `valkey_url` and `s3_config` are added, each with a single skip point.
- **C-28** File-map reconciliation. `stores/pg/models.py` → `stores/pg/rows.py` and
  `api/routes.py` → `api/routes_v1.py` (both renamed to the names §1/§5.2/§9.3 already gave
  them — renamed, not shimmed, because a re-exporting alias leaves two importable names for one
  module). `api/models.py`, `ingest/runner.py` and `stores/valkey/client.py` were built but
  absent from §1; rows added. §13.2's test map is rewritten to the tree as built.
- **C-29** `Repo.get_principal_by_external_ref` gains a keyword-only
  `kind: Literal["oidc_sub","api_key"] | None = None`. `principal`'s constraint is
  `UNIQUE(kind, external_ref)`; the one-argument form could match two rows, and its fail-closed
  answer (return None, refuse to guess) denied authentication to BOTH identities — a DoS an IdP
  could trigger by minting one `sub` equal to a server-minted key id. The default keeps the
  original signature legal; every caller in the tree passes `kind`.
- **C-30** `Repo.create_agent_registration(...)` — agent_type upsert + principal insert +
  agent_registration insert in ONE transaction, replacing three composed `Repo` calls from
  `POST /admin/agents/register`. A 409 on the third call previously committed an orphan
  `agent_type` and an orphan `api_key` principal whose `key_hash` was live but whose plaintext
  had been returned to nobody. The agent_type half is `ON CONFLICT (project_id, name) DO UPDATE
  ... RETURNING`, which is what makes §9.3's "creates agent_type if new" true. `AdminPort`
  declares this method instead of the three, so the non-atomic composition is unreachable from
  a route.
- **C-31** `POST /v1/invalidation` persists. PLAN.md §3 lists the route and PLAN.md §5 defines
  `invalidation_event`; §9.3's route table does neither, and the route shipped returning 202
  "accepted" while discarding the body. Now `Repo.insert_invalidation_event(project_id,
  event_type, selector)` — a synchronous scoped insert, not a queue write, because §14 forbids
  a fourth topic and §14's "do NOT write synchronously" names trace/outcome rows specifically.
  `event_id` is server-generated, per the column's own DDL comment.
- **C-32** `ScopedRepo.get_trace_index(run_id, *, for_update=False)`; `ingest.trace_writer`
  always passes `True`. `_TRACE_INDEX_UPSERT_SQL` replaces `path` wholesale (jsonb cannot be
  per-key merged by ON CONFLICT), so two workers holding different batches of one run each read
  the pre-batch `path` and the last commit wins — dropping the loser's `payload_refs` entry,
  the only pointer to that batch's ciphertext. `FOR UPDATE` alone is insufficient (it locks
  nothing when the row does not exist yet, the first-batch race), so the read also takes a
  transaction-scoped advisory lock on the (project, run) pair.
- **C-33** `api.models.MAX_SEQ` lowered from int4 max to `1_000_000`, matching
  `ingest.trace_writer.MAX_TRACE_SEQ`. Accepting a seq the consumer will refuse means answering
  202 and dead-lettering out of the caller's sight. Mirrored rather than imported because `api`
  must not depend on `ingest`; `test_integration_seams.py` asserts the two agree.
- **C-34** `SigV4Signer.sign`'s `now` is required, and `S3TraceStore` takes an injectable
  `clock: Clock` defaulting to `SystemClock`. The optional `now` fell back to
  `datetime.now(UTC)` on every real signed request — the last bare wall-clock call in `src/`
  and, under hard rule 4, a component the Phase 2 soak could not replay.
- **C-35** `FeedbackIn` rejects a naive `event.occurred_at` at the wire.
  `domain.events._EventBase.ts` already rejects naive timestamps but `FeedbackEvent` uses a
  different base, and `domain/` is frozen. `outcome_event.occurred_at` is `timestamptz`, so
  Postgres would reinterpret a naive value in the session TimeZone and move the event by hours
  — silently, on the column T+2-day feedback attach joins by. `ingest.outcome_intake` still
  refuses it too, for envelopes that arrive from a replay tool rather than this route.

### Known and NOT fixed in Phase 0 (each has a tripwire test)

- **`retrieval_event PRIMARY KEY (project_id, run_id)`** permits one row per run, against its
  own DDL comment and PLAN.md §5 ("one row per /v1/retrieve call"), and
  `Repo.insert_retrieval_event` has no ON CONFLICT clause. Unreachable in Phase 0 (the retrieve
  stub mints a fresh server-side run_id per call); a live invariant-2 violation the moment
  C-26's `run_id_origin: "sdk"` ships or an agent retrieves twice in one run. Not fixed here
  because it is partitioned-table DDL that cannot be executed, let alone tested, without a
  Postgres. THE highest-priority Phase 1 schema change.
  Same shape: `injection_log PRIMARY KEY (project_id, run_id, memory_id)` with
  `ON CONFLICT DO NOTHING` silently drops a re-injection of one memory within a run.
- **`trace_index` has no `first_seen_at`.** `find_runs_missing_sentinel` falls back to the
  epoch when `started_at IS NULL`, so a run whose first batch carried no `run_start` is
  sweepable to `incomplete` before its `run_start` could plausibly arrive.
- **`POST /admin/projects`** composes registry row → partitions → project KEK with no rollback;
  a failure after the first step leaves a project that cannot be written to. Spanning a
  transaction across the registry, DDL, and the key manager needs a composition tool no module
  owns.
- **`GET /export/project`** can truncate silently under a 200: an exception raised after the
  first byte cannot reach the exception handlers, because the response has already started.
  Fixing it needs a terminating-sentinel format decision.
- **`harness/phase0_gate.py` has no test of its own** (§13.2). Its verdict logic is the single
  most correctness-critical thing in the phase.
