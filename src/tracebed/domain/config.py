"""Typed configuration surface (PHASE-0 Task 2; PHASE0-CONTRACT.md §3.4).

`TracebedSettings` is the process-defaults layer: `pydantic-settings`, env
prefix ``TB_``, nested delimiter ``__``, `extra="forbid"` at every level so
an unknown key — a typo, a stale env var from a removed field — is a hard
startup failure instead of a silently ignored setting.

`ConfigResolver.effective()` layers process defaults -> `project_config` ->
`agent_type_config` -> a read-only killswitch overlay into an
`EffectiveConfig` snapshot. It takes a `ConfigStorePort` callable-style
protocol rather than a concrete store, which is what makes it testable with
zero database (`Repo` satisfies the protocol structurally; the DO-NOT list
in §14 forbids this module from importing `stores.pg` at all).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Final, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import AgentTypeId, ProjectId

__all__ = [
    "OVERRIDABLE_SECTIONS",
    "AbstentionConfig",
    "ApiConfig",
    "AuthConfig",
    "BudgetConfig",
    "CacheConfig",
    "ConfigResolver",
    "ConfigStorePort",
    "DashboardConfig",
    "DerivedConfig",
    "EffectiveConfig",
    "EmbeddingConfig",
    "KillswitchConfig",
    "LLMProviderConfig",
    "LifecycleConfig",
    "PromotionConfig",
    "ProposalConfig",
    "QueueConfig",
    "RetirementConfig",
    "RetrievalConfig",
    "ScoreConfig",
    "ScoringConfig",
    "SessionConfig",
    "SpendConfig",
    "StorageConfig",
    "TierAConfig",
    "TraceStoreConfig",
    "TracebedSettings",
]


class _StrictModel(BaseModel):
    """Base for every nested config section: unknown keys are a hard error, and
    a section instance cannot be mutated after construction.

    `extra="forbid"` is what makes `TB_STORAGE__NOT_A_FIELD=x` fail startup
    instead of being silently swallowed — the same guarantee
    `TracebedSettings.model_config` gives at the top level, applied at every
    nesting depth (contract requirement: "extra='forbid' at every level").

    `frozen=True` is load-bearing for invariant 7 ("no admin bypass in code")
    and for §3.4's "frozen snapshot" claim. `EffectiveConfig` alone being
    frozen only stopped `cfg.retirement = ...`; every threshold the state
    machine reads lives one level down, so `cfg.retirement.q_threshold = 0.0`
    — a governance bypass with no audit trail — was still legal. It now
    raises. Shallow by necessity: a `dict`-valued field (`slot_caps`,
    `adapter_weights`, `ttl_class`, `per_worker_overrides`) is still a plain
    mutable dict, because `MappingProxyType` is not JSON-serialisable by
    pydantic and this module's models must round-trip through
    `model_dump()`/`model_dump_json()`. What protects those is that every
    `effective()` call rebuilds them from a fresh `model_dump()`, so a
    mutation can never travel between projects — proved by
    `test_config.py::test_override_for_one_project_does_not_bleed_into_another`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- #
# Deployment-level sections (NOT overridable via project/agent_type config —
# see OVERRIDABLE_SECTIONS below and C-03).
# --------------------------------------------------------------------------- #


class ApiConfig(_StrictModel):
    """The API process's own listen settings."""

    port: int = 8110
    workers: int = 2


class DashboardConfig(_StrictModel):
    """The separate dashboard app's listen settings (D-031)."""

    port: int = 8111


class AuthConfig(_StrictModel):
    """Auth mode selection (D-029) and the bootstrap admin-key env var name."""

    oidc_jwks_url: str | None = None
    oidc_issuer: str | None = None
    api_key_mode: bool = True
    admin_key_env: str = "TB_ADMIN_KEY"
    """C-02: the only config field added beyond Task 2's listing — names the
    env var holding the static bootstrap admin credential (§9.1)."""


class TraceStoreConfig(_StrictModel):
    """Trace-blob storage driver selection (§6.3, §11)."""

    driver: Literal["fs", "s3"] = "fs"
    root: Path = Path("./tracestore")
    bucket: str | None = None
    endpoint: str | None = None
    region: str = "us-east-1"
    access_key_env: str = "TB_S3_ACCESS_KEY"
    secret_key_env: str = "TB_S3_SECRET_KEY"  # noqa: S105 - an env var *name*, not a secret


class StorageConfig(_StrictModel):
    """Postgres, Valkey, and trace-store wiring. `pg_dsn` is required."""

    pg_dsn: str
    valkey_url: str = "valkey://localhost:6379/0"
    tracestore: TraceStoreConfig = Field(default_factory=TraceStoreConfig)


class EmbeddingConfig(_StrictModel):
    """The embedding pin (D-007): model id/version/dim stamped on every row."""

    model_id: str = "gemini-embedding-2"
    model_version: str
    dim: int = 768
    driver: Literal["gemini", "onnx-local"] = "gemini"
    onnx_model_path: Path | None = None
    onnx_model_hash: str | None = None


class LLMProviderConfig(_StrictModel):
    """Judge/distiller worker model selection (D-008), OpenAI-compatible."""

    base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai/"
    api_key_env: str = "TB_LLM_API_KEY"
    judge_model: str = "gemini-3.1-pro"
    distiller_model: str = "gemini-3.1-pro"
    per_worker_overrides: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Overridable sections — layered by ConfigResolver via project_config /
# agent_type_config dotted overrides (C-03). Keep this set and
# `_SECTION_MODELS` below in exact agreement with the contract's listing.
# --------------------------------------------------------------------------- #


class RetrievalConfig(_StrictModel):
    """Retrieval budgets, RRF fusion constants (D-009), and HNSW scan knobs."""

    # `ge=1`, not merely documented: `hotpath.budget.Deadline` refuses a
    # non-positive total budget outright (a zero budget is a broken config row,
    # not an instant timeout), and `hotpath.pipeline` catches that refusal as
    # the ladder's store-error rung. Without the constraint, a `project_config`
    # override of `retrieval.total_budget_ms: 0` is reported to an operator as
    # "the store failed" on every single request. Rejecting it where the
    # override is parsed names the misconfiguration instead (`ConfigResolver`
    # raises `ConfigError` quoting the offending section).
    total_budget_ms: int = Field(default=300, ge=1)
    embed_timeout_ms: int = Field(default=200, ge=1)
    rrf_k: int = 60
    rrf_weight_vector: float = 1.0
    rrf_weight_lexical: float = 1.0
    arm_top_n: int = 50
    fused_top_n: int = 20
    hnsw_iterative_scan: bool = True
    hnsw_max_scan_tuples: int = 20_000


class AbstentionConfig(_StrictModel):
    """Calibrated-signal abstention thresholds (D-015): similarity, BM25, rarity."""

    cos_threshold: float = 0.60
    bm25_sat_k: float = 10.0
    bm25_norm_threshold: float = 0.50
    rarity_min_shared_terms: int = 2
    rarity_max_df_pct: float = 2.0
    rarity_min_corpus_docs: int = 200
    target_abstention_pct: float = Field(default=50.0, ge=0.0, le=100.0)
    """PLAN.md §6 lists this field with the documented target ">= 50". It is a
    REPORTING target, not a threshold any decision reads: nothing in `hotpath/`
    branches on it, because an abstention rate is a property of a *population* of
    retrievals and the hot path only ever sees one. It exists so that the four
    places that quote the number -- `harness.negative_probes` (which compares the
    measured rate against it), `harness.phase1_gate`, `hotpath.abstention
    .measured_abstention_rate`'s docstring and `workers.lift` -- read one config
    field instead of each carrying a private copy of a literal. Bounded to a real
    percentage: `abstention` is an `OVERRIDABLE_SECTIONS` member, so a
    `project_config` jsonb row reaches this field, and a target of 900 would make
    the probe gate unpassable while a target of -1 would make it vacuous."""


class ScoreConfig(_StrictModel):
    """Composite ranking-score weights for injected candidates."""

    w_sim: float = 0.40
    w_q: float = 0.30
    w_recency: float = 0.15
    w_validity: float = 0.15
    recency_half_life_days: int = 14


class BudgetConfig(_StrictModel):
    """Context-window token budget: static prefix vs. dynamic block, per-slot caps."""

    total_tokens: int = 1200
    static_prefix: int = 700
    static_prefix_prefs: int = 200
    static_prefix_lessons: int = 500
    dynamic: int = 500
    slot_caps: dict[str, int] = Field(
        default_factory=lambda: {
            "fact": 250,
            "exemplar": 150,
            "pitfall": 100,
            "candidate_note": 100,
            "jit_lesson": 150,
        }
    )


class ScoringConfig(_StrictModel):
    """The Q-update formula's constants (D-011): learning rate, adapter trust weights."""

    alpha: float = Field(default=0.3, gt=0.0, le=1.0)
    q_start: float = Field(default=0.5, ge=0.0, le=1.0)
    adapter_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "verdict": 1.0,
            "correction_adapter": 0.8,
            "downstream": 0.3,
            "implicit": 0.0,
        }
    )
    contribution_rubric: dict[str, float] = Field(
        default_factory=lambda: {"NONE": 0.0, "PARTIAL": 0.5, "FULL": 1.0}
    )
    """PLAN.md §6's `scoring.contribution_rubric` (judge in {0, 0.5, 1.0}). The mapping lived
    as `workers.contribution_judge._RUBRIC`, a module constant -- the magic-numbers-in-code
    shape §6's header forbids, and the same defect D-089 found, fixed and logged for
    `abstention.target_abstention_pct`. `workers.contribution_judge` now derives its rubric
    from this field's default, and `tests/phase3/test_contribution_judge.py` pins the two
    together so they cannot drift.

    A dict rather than a set because the judge's wire protocol is a TOKEN ("FULL") mapped to a
    factor; the factors alone would not let an operator see or change which token means what."""
    contribution_judge_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    """The other half of §6's rubric line ("temp 0"). Temperature 0 is not a tuning preference
    here: a contribution verdict that varies between two identical calls makes Q irreproducible
    for the same evidence."""
    updates_per_memory_per_day: int = Field(default=1, ge=1)
    """PLAN.md §6 states 1. Bounded below for the same reason every other
    threshold in this module is (D-071/D-075/D-080: an override dies where it
    is parsed, so `ConfigResolver` can name the offending section): `scoring`
    is an `OVERRIDABLE_SECTIONS` member, so a `project_config` jsonb row
    reaches this field, and 0 or a negative value makes `run_scorer_batch`'s
    `scored_today >= cap` true on every call. That does not merely narrow the
    cap -- it turns scoring OFF for the whole project, silently, with every
    worker still running and every gate still green.

    NO UPPER BOUND IS SET, and that is a reported gap rather than an
    oversight. Widening is the DANGEROUS direction -- the daily cap is what
    bounds how fast one feedback source can walk a memory's Q, and D-021 sizes
    its four-calendar-day retirement window on this being 1 -- but PLAN.md §6
    gives this field a default and no range, so any ceiling here would be a
    number this module invented for a governed threshold. Recorded in
    DECISIONS.md (D-083) for a human rather than guessed at."""


class PromotionConfig(_StrictModel):
    """`candidate -> validated` thresholds (state_machine §3.9)."""

    min_outcomes: int = 2
    failure_lesson_outcomes: int = 1
    min_distinct_principals: int = 2


class RetirementConfig(_StrictModel):
    """`validated -> retired` thresholds, including the K-distinct-principals floor (D-021)."""

    q_threshold: float = 0.25
    min_scored_uses: int = 4
    min_distinct_principals: int = 3


class LifecycleConfig(_StrictModel):
    """Decay/TTL constants governing quarantine, candidacy, and staleness (D-012).

    Bounded for the same reason `RetrievalConfig.total_budget_ms` is (D-071):
    `lifecycle` is an `OVERRIDABLE_SECTIONS` member, so every value here is
    reachable from a `project_config` jsonb row. `decay_pct_per_idle_week`
    outside [0, 100] inverts the decay curve `workers.sweeps._decayed_q_value`
    computes -- above 100 the per-week factor goes negative (a Q that flips
    sign each week), below 0 idleness *raises* Q. The sweep clamps the result
    into [0, 1] defensively, but a clamp cannot recover the intent; refusing
    the override names the broken row instead. A TTL of 0 days would sweep a
    row on the same tick it was written, so the day counts are `ge=1`.
    """

    decay_pct_per_idle_week: float = Field(default=5, ge=0, le=100)
    archive_floor: float = Field(default=0.15, ge=0.0, le=1.0)
    quarantine_ttl_days: int = Field(default=30, ge=1)
    candidate_ttl_days: int = Field(default=45, ge=1)
    revalidation_age_days: int = Field(default=30, ge=1)


class DerivedConfig(_StrictModel):
    """Derived-state guardrails: movement clamp, divergence alarm (D-022).

    Constrained here, not only at the consumer. `derived` is overridable per
    project and per agent type, and each degenerate value silently DISABLES a
    control rather than failing loudly: `keep_versions=0` prunes away the very
    row `workers.derived_state` reads to rate-bound the next write, so every
    update looks like a first write and nothing is ever clamped -- the movement
    clamp removed by a knob whose documented purpose is "debugging need", with
    every dashboard still showing a clamp configured. `DerivedStateWriter`
    keeps its own refusal as defence in depth (it can be handed a
    `model_construct`-ed config, or a future non-pydantic source), but the
    override has to die where it is parsed so `ConfigResolver` can name the
    offending section.
    """

    baseline_max_delta_pct: float = Field(default=10, gt=0, allow_inf_nan=False)
    clamp_alert_consecutive: int = Field(default=3, ge=1)
    divergence_alarm_pct: float = Field(default=25, ge=0, allow_inf_nan=False)
    keep_versions: int = Field(default=20, ge=1)


class ProposalConfig(_StrictModel):
    """`propose_memory` rate caps (D-023)."""

    per_run_cap: int = 2
    per_project_daily_cap: int = 50


class TierAConfig(_StrictModel):
    """Tier A operational-note caps (D-019)."""

    candidate_cap_per_run: int = Field(default=1, ge=0)
    """`ge=0`, not `ge=1`: zero is a meaningful setting (a project that wants
    the Tier A lane to observe and merge but never emit a new candidate), while
    a negative cap would make `CandidateCapTracker` reject every run with no
    way for an operator to tell that from "the extractor found nothing"."""


class KillswitchConfig(_StrictModel):
    """Holdout-arm and statistical-trigger constants for the kill switch (D-027)."""

    holdout_pct: float = 5
    salt_env: str = "TB_HOLDOUT_SALT"
    window_days: int = 14
    min_cell_n: int = 200
    correction: str = "benjamini-hochberg"
    fdr_alpha: float = Field(default=0.05, gt=0.0, lt=1.0)
    """The level `correction` corrects AT. PLAN.md §6 names the METHOD and not the level, so
    this lived as `workers.lift.DEFAULT_BH_ALPHA` -- a governed threshold as a module constant,
    which is exactly what hard rule 12 forbids and what left an operator believing
    `correction` controlled something it does not (it is read only to print a label).
    0.05 is not invented here: D-027 reasons explicitly about "~1 cell in 20 per window by
    chance". `workers.lift` now derives its default from this field, so the two cannot disagree.
    Bounded open at both ends: alpha=0 can never fire and alpha=1 always fires."""
    confidence_level: float = Field(default=0.95, gt=0.5, lt=1.0)
    """The one-sided confidence level every lower bound is computed at, for the same reason
    and with the same history as `fdr_alpha`. Floored above 0.5 because a "confidence" bound
    below the coin flip is not a bound; capped below 1.0 because 1.0 is unattainable and would
    make the interval infinite."""


class SpendConfig(_StrictModel):
    """Daily LLM spend cap, recorded by `SpendMeter` (enforcement is Phase 3)."""

    daily_llm_cap_usd: float = 25.0


class CacheConfig(_StrictModel):
    """Valkey TTL classes by cache kind."""

    ttl_class: dict[str, str] = Field(
        default_factory=lambda: {"intel": "24h", "registry": "14d"}
    )


class SessionConfig(_StrictModel):
    """Session idle timeout and working-memory offload threshold."""

    idle_ttl_min: int = 60
    offload_threshold_tokens: int = 20_000


class QueueConfig(_StrictModel):
    """`work_queue` lease/retry constants (§5.3)."""

    lease_seconds: int = Field(default=30, ge=1)
    max_attempts: int = Field(default=5, ge=1)
    batch_size: int = Field(default=100, ge=1)


class WorkersConfig(_StrictModel):
    """Cadences and per-sweep sizing for the periodic learning plane (`workers.scheduler`).

    WHY THIS SECTION EXISTS. `workers/scheduler.py`, `workers/runner.py` and
    `workers/registry.py` each carried the same standing CONTRACT GAP: "PLAN.md §6's config
    table has no field for how often the TTL sweep runs (only the TTL *durations*, which are
    `domain.state_machine` guard thresholds, not sweep periods) ... inventing one here would be
    exactly hard rule 4's 'a number that is not there is a contract_gap, not a licence to invent
    a literal'." That refusal was right, and it is also why `workers.Scheduler` was constructed
    by nothing: a job needs a cadence, a cadence is a number, and there was nowhere legitimate
    to put one. This section is that place. Every interval below is now a *declared* number a
    deployment can see, override per environment, and read back off `/admin/config` -- not a
    literal buried in `runner.run()`'s body.

    WHY IT IS NOT IN `OVERRIDABLE_SECTIONS`. Deliberate, and the same reasoning
    `EffectiveConfig`'s docstring already gives for `storage`/`llm`/`auth`: one `Scheduler`
    instance serves every project in the process, so "how often does the sweep thread tick" is
    not a per-project quantity and a `project_config` row claiming otherwise would be a knob
    that silently does nothing. The *thresholds* the sweeps evaluate (`lifecycle.*`,
    `retirement.*`, `promotion.*`) stay overridable exactly as before -- what a sweep decides is
    a project's business; how often the process wakes up is the deployment's.

    Bounds. Every interval is `ge=1` minute: a zero or negative interval is refused by
    `ScheduledJob.__post_init__` anyway, and a sub-minute sweep over every project in a
    deployment is a load profile nobody would choose on purpose. There is no upper bound --
    a very long interval is a deliberate "effectively off" setting, and refusing it would take
    away the only way to disable one job without editing code.
    """

    sweep_interval_minutes: int = Field(default=60, ge=1)
    """`workers.sweeps` -- quarantine/candidate TTL expiry, idle Q decay, archive floor."""

    revalidation_interval_minutes: int = Field(default=360, ge=1)
    """`workers.revalidation` -- idle-triggered re-verification (D-113)."""

    consolidation_interval_minutes: int = Field(default=1_440, ge=1)
    """`workers.consolidator` -- near-duplicate merge. Daily by default: consolidation
    rewrites provenance, and doing it more often than the distiller produces new material
    buys nothing."""

    prefix_rebuild_interval_minutes: int = Field(default=60, ge=1)
    """`workers.prefix_builder` -- the static prefix every run of an agent type receives."""

    derived_state_interval_minutes: int = Field(default=1_440, ge=1)
    """`workers.derived_state` -- baseline refresh, movement-clamped."""

    gc_interval_minutes: int = Field(default=1_440, ge=1)
    """`workers.gc` -- tombstone/blackboard/dead-letter reclamation."""

    embedding_interval_minutes: int = Field(default=5, ge=1)
    """`workers.embedder` -- the ANN arm's write side. Much shorter than the governance
    sweeps on purpose: a memory is retrievable by BM25 the moment it is written but invisible
    to the vector arm until this runs, so the interval is the ANN arm's staleness window, not
    a maintenance cadence."""

    embedding_batch_limit: int = Field(default=200, ge=1)
    """Rows per project per embedding sweep (`Embedder.run(..., limit=)`). Bounds the work one
    tick can do so a large backfill is spread across ticks instead of blocking the thread."""

    embedding_max_batch: int = Field(default=32, ge=1)
    """Texts per `EmbeddingPort.embed` call. Distinct from `embedding_batch_limit`: one sweep
    of `embedding_batch_limit` rows issues `ceil(limit / max_batch)` provider calls."""

    embedding_timeout_ms: int = Field(default=10_000, ge=1)
    """Per-call budget for a BACKGROUND embedding request. Deliberately not
    `retrieval.embed_timeout_ms` (200 ms), which PLAN.md invariant 1 defines as the HOT PATH's
    query-embedding sub-budget for a single short string; reusing it here would starve a batch
    of `embedding_max_batch` documents to a budget sized for one query."""

    embedding_usd_per_1k_tokens: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    """Price used to record embedding spend on `spend_ledger`. Defaults to 0.0, which is a
    HONEST default rather than a free lunch: this repository has no price table anywhere
    (`SpendConfig` has a cap and no prices -- `workers/distiller.py` documents the same gap),
    and a made-up non-zero price would put a fabricated number into the ledger the daily cap is
    computed from. Zero means "spend is recorded as tokens, not dollars" until a deployment
    supplies its provider's real rate."""

    corroboration_interval_minutes: int = Field(default=30, ge=1)
    """`workers.corroboration` -- the shadow-confirmation writer, the only non-human route out
    of quarantine."""

    shadow_validation_interval_minutes: int = Field(default=30, ge=1)
    """`workers.shadow_validator` -- judges the evidence the corroboration writer records."""

    killswitch_interval_minutes: int = Field(default=1_440, ge=1)
    """`workers.killswitch` -- the daily grid evaluation."""

    scheduler_tick_seconds: float = Field(default=1.0, gt=0.0, allow_inf_nan=False)
    """How often the scheduler thread calls `Scheduler.tick()`. Not a job cadence -- it is the
    resolution at which the cadences above are observed, so it must be well below the shortest
    of them. Seconds, not minutes, because it is a polling interval of the same class as
    `ingest.runner.RunnerConfig.poll_interval_s`."""


# --------------------------------------------------------------------------- #
# The settings root.
# --------------------------------------------------------------------------- #


class TracebedSettings(BaseSettings):
    """Process-defaults config layer: env prefix ``TB_``, nested delimiter ``__``.

    `extra="forbid"` here (and on every nested `_StrictModel`) rejects any
    env var under the `TB_` prefix that does not map to a declared field —
    the contract's "unknown key rejected" test exercises exactly this.
    `storage` and `embedding` have no default: `TB_STORAGE__PG_DSN` and
    `TB_EMBEDDING__MODEL_VERSION` must be set for the process to start.
    """

    model_config = SettingsConfigDict(
        env_prefix="TB_", env_nested_delimiter="__", extra="forbid"
    )

    api: ApiConfig = Field(default_factory=ApiConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    storage: StorageConfig
    embedding: EmbeddingConfig
    llm: LLMProviderConfig = Field(default_factory=LLMProviderConfig)
    retrieval: RetrievalConfig = Field(default_factory=RetrievalConfig)
    abstention: AbstentionConfig = Field(default_factory=AbstentionConfig)
    score: ScoreConfig = Field(default_factory=ScoreConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    promotion: PromotionConfig = Field(default_factory=PromotionConfig)
    retirement: RetirementConfig = Field(default_factory=RetirementConfig)
    lifecycle: LifecycleConfig = Field(default_factory=LifecycleConfig)
    derived: DerivedConfig = Field(default_factory=DerivedConfig)
    proposals: ProposalConfig = Field(default_factory=ProposalConfig)
    tier_a: TierAConfig = Field(default_factory=TierAConfig)
    killswitch: KillswitchConfig = Field(default_factory=KillswitchConfig)
    spend: SpendConfig = Field(default_factory=SpendConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    queue: QueueConfig = Field(default_factory=QueueConfig)
    # Deployment-level, like `storage`/`llm`/`auth` and unlike `queue`: see
    # WorkersConfig's docstring for why a per-project scheduler cadence would be a
    # knob that silently does nothing. Absent from `_SECTION_MODELS` below, which is
    # the enforcement -- `_apply_override` refuses any dotted key whose first segment
    # is outside `OVERRIDABLE_SECTIONS`.
    workers: WorkersConfig = Field(default_factory=WorkersConfig)


# --------------------------------------------------------------------------- #
# Layered resolution (§3.4 / C-03).
# --------------------------------------------------------------------------- #

_SECTION_MODELS: Final[dict[str, type[_StrictModel]]] = {
    "retrieval": RetrievalConfig,
    "abstention": AbstentionConfig,
    "score": ScoreConfig,
    "budget": BudgetConfig,
    "scoring": ScoringConfig,
    "promotion": PromotionConfig,
    "retirement": RetirementConfig,
    "lifecycle": LifecycleConfig,
    "derived": DerivedConfig,
    "proposals": ProposalConfig,
    "tier_a": TierAConfig,
    "killswitch": KillswitchConfig,
    "spend": SpendConfig,
    "cache": CacheConfig,
    "session": SessionConfig,
    "queue": QueueConfig,
}

OVERRIDABLE_SECTIONS: Final[frozenset[str]] = frozenset(_SECTION_MODELS)
"""The nested sections a `project_config`/`agent_type_config` dotted override
may target. Deployment-level sections (`embedding`, `llm`, `storage`,
`auth`, `api`, `dashboard`) are deliberately absent — see §3.4's
EffectiveConfig note and C-03."""


@runtime_checkable
class ConfigStorePort(Protocol):
    """What `ConfigResolver` needs from a store — `Repo` satisfies this structurally.

    Declared here, not in `adapters/ports.py`, per C-18: `ports.py` must stay
    import-clean of anything besides `domain` types, and this protocol's
    only real implementation (`Repo`) lives with the registry tables this
    module must not import.
    """

    def get_project_config(self, project_id: ProjectId) -> Mapping[str, object]:
        """Dotted-key -> JSON-value overrides set at the project level."""
        ...

    def get_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> Mapping[str, object]:
        """Dotted-key -> JSON-value overrides set at the agent-type level."""
        ...

    def get_killswitch_overlay(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None
    ) -> Mapping[str, bool]:
        """mem_type -> disabled, from `killswitch_state`. Read-only to resolution."""
        ...


class EffectiveConfig(BaseModel):
    """Frozen snapshot of every overridable section plus the killswitch overlay.

    Deployment-level sections (`embedding`, `llm`, `storage`, `auth`, `api`,
    `dashboard`) are intentionally absent — those are settled at process
    start, not per-project. Their absence is the enforcement, not a
    convention: because `_apply_override` refuses any dotted key whose first
    segment is outside `OVERRIDABLE_SECTIONS`, a row in `project_config`
    cannot repoint `storage.pg_dsn` at another tenant's database or turn
    `auth.api_key_mode` off (invariant 4 — project config is caller-adjacent
    data and must not reach the wiring layer).

    `killswitch_overlay` is populated exclusively from
    `ConfigStorePort.get_killswitch_overlay`; no dotted override can ever
    reach it, because `"killswitch_overlay"` is not a key in
    `OVERRIDABLE_SECTIONS` (only the `killswitch` *section*, its sibling, is
    overridable — a caller cannot forge a live kill-switch disable through
    the same channel that tunes `holdout_pct`). It is copied out of the store
    at resolution time, so neither side can mutate the other's dict; it is
    not deep-frozen (see `_StrictModel` on why `MappingProxyType` is not an
    option here).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    retrieval: RetrievalConfig
    abstention: AbstentionConfig
    score: ScoreConfig
    budget: BudgetConfig
    scoring: ScoringConfig
    promotion: PromotionConfig
    retirement: RetirementConfig
    lifecycle: LifecycleConfig
    derived: DerivedConfig
    proposals: ProposalConfig
    tier_a: TierAConfig
    killswitch: KillswitchConfig
    spend: SpendConfig
    cache: CacheConfig
    session: SessionConfig
    queue: QueueConfig
    killswitch_overlay: Mapping[str, bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _q_seed_must_sit_above_the_archive_floor(self) -> EffectiveConfig:
        """`scoring.q_start` and `lifecycle.archive_floor` are independently
        overridable, and no single-field constraint can see the pair.

        `workers.sweeps._decayed_q_value` anchors the idle-decay curve on
        `q_start` and archives a row once the curve reaches `archive_floor`.
        A project whose seed is at or below its floor therefore has EVERY idle
        `validated` memory archived after its first idle week -- the whole
        vault silently emptied by two individually plausible override rows.
        The sweep clamps the computed value into [0, 1] so nothing corrupt is
        written, but a clamp cannot distinguish "decayed to the floor" from
        "started there", which is exactly why the pair has to be rejected
        rather than repaired.
        """
        if self.scoring.q_start <= self.lifecycle.archive_floor:
            raise ValueError(
                "scoring.q_start "
                f"({self.scoring.q_start}) must be strictly above "
                f"lifecycle.archive_floor ({self.lifecycle.archive_floor}): a seed "
                "at or below the floor archives every memory on its first idle sweep"
            )
        return self


def _apply_override(merged: dict[str, dict[str, object]], key: str, value: object) -> None:
    """Write one dotted-path override (`"budget.slot_caps.fact"`) into `merged`.

    Raises `ConfigError` for anything C-03 rules out: a key with no field
    component, a first segment that is not an overridable section, or a
    path that tries to walk through a non-mapping value. Value-level
    validity (wrong type, unknown leaf field) is deliberately NOT checked
    here — that happens once, uniformly, when the section model is
    reconstructed in `ConfigResolver.effective()`, via the section's own
    `extra="forbid"`.
    """
    parts = key.split(".")
    if len(parts) < 2 or not all(parts):
        raise ConfigError(f"override key must be a dotted 'section.field' path: {key!r}")
    section, *rest = parts
    if section not in OVERRIDABLE_SECTIONS:
        raise ConfigError(
            f"override key {key!r} does not target an overridable section "
            f"(one of {sorted(OVERRIDABLE_SECTIONS)})"
        )
    node = merged[section]
    for part in rest[:-1]:
        nxt = node.setdefault(part, {})
        if not isinstance(nxt, dict):
            raise ConfigError(f"override key {key!r} traverses a non-mapping value")
        node = nxt
    node[rest[-1]] = value


class ConfigResolver:
    """Layers process defaults -> `project_config` -> `agent_type_config` -> killswitch overlay.

    `effective(project_id, agent_type_id)` is deliberately not memoised —
    Phase 0 calls it per-request, and the store is the source of truth for
    anything that changed since the last call (an operator toggling a
    killswitch entry, for instance). Each call also rebuilds its working copy
    from `settings.<section>.model_dump()`, which is what keeps one project's
    overrides out of the next project's snapshot (invariant 4).
    """

    def __init__(self, settings: TracebedSettings, store: ConfigStorePort) -> None:
        self._settings = settings
        self._store = store

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig:
        """Resolve the layered config for one (project, agent_type) pair.

        Precedence (C-03): process defaults, then `project_config`, then
        `agent_type_config` (skipped entirely when `agent_type_id` is
        `None`), then the killswitch overlay applied last and read-only.
        Raises `ConfigError` for any override this resolver cannot make
        sense of — nothing is ever silently dropped.
        """
        merged: dict[str, dict[str, object]] = {
            section: getattr(self._settings, section).model_dump()
            for section in OVERRIDABLE_SECTIONS
        }

        for key, value in self._store.get_project_config(project_id).items():
            _apply_override(merged, key, value)

        if agent_type_id is not None:
            for key, value in self._store.get_agent_type_config(
                project_id, agent_type_id
            ).items():
                _apply_override(merged, key, value)

        sections: dict[str, object] = {}
        for section, model_cls in _SECTION_MODELS.items():
            try:
                # model_validate, not model_cls(**mapping): override keys come
                # from a jsonb column and are therefore arbitrary strings, and
                # keyword-expanding them makes the failure mode depend on
                # pydantic's __init__ signature rather than on extra="forbid".
                sections[section] = model_cls.model_validate(merged[section])
            except ValidationError as exc:
                raise ConfigError(
                    f"invalid override(s) in section {section!r}: {exc}"
                ) from exc

        overlay = self._store.get_killswitch_overlay(project_id, agent_type_id)
        try:
            # Cross-section constraints (see EffectiveConfig's validators) can
            # only fire here, once every section has been rebuilt. Translating
            # to ConfigError keeps one exception type for "this project's
            # config rows do not make sense", whichever layer noticed.
            return EffectiveConfig(killswitch_overlay=dict(overlay), **sections)
        except ValidationError as exc:
            raise ConfigError(f"invalid override combination across sections: {exc}") from exc
