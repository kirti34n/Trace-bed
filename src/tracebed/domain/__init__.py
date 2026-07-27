"""Tracebed domain layer: pure types and logic, no I/O, no framework imports.

Re-exports the stable public names of the four modules this chunk may touch:
`ids` and `clock` (both [frozen]) plus `errors` and `config` (owned by chunk
domain-config).

Modules owned by other Phase 0 chunks — `enums`, `scope`, `canonical`,
`events`, `memory`, `scan`, `signatures`, `state_machine` — are deliberately
NOT re-exported, even the ones that have since landed. Two reasons, both
merge-safety: this file would otherwise pin another chunk's export surface
while that chunk is still free to change it, and a parallel build can have
some of those modules missing (`memory` and `scope` are absent as of this
pass), which would turn `import tracebed.domain` into an ImportError for
everyone. Import those modules by path — `from tracebed.domain.enums import
MemType` — not through this package. PHASE0-CONTRACT.md §1 assigns
`domain/__init__.py` to no chunk at all; reconciling the export surface is a
merge-time job, recorded as a contract_gap.
"""

from __future__ import annotations

from tracebed.domain.clock import Clock, FakeClock, SystemClock
from tracebed.domain.config import (
    AbstentionConfig,
    ApiConfig,
    AuthConfig,
    BudgetConfig,
    CacheConfig,
    ConfigResolver,
    ConfigStorePort,
    DashboardConfig,
    DerivedConfig,
    EffectiveConfig,
    EmbeddingConfig,
    KillswitchConfig,
    LifecycleConfig,
    LLMProviderConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    StorageConfig,
    TierAConfig,
    TracebedSettings,
    TraceStoreConfig,
)
from tracebed.domain.errors import (
    AuthenticationFailed,
    BudgetExceeded,
    CapExceeded,
    ConfigError,
    CrossEpochComparison,
    DuplicateRegistration,
    EmbeddingTimeout,
    GuardNotSatisfied,
    IllegalTransition,
    MasterKeyMissing,
    NotFound,
    ProvenanceIncomplete,
    QueueFull,
    ScanRejected,
    ScanVerdictForgery,
    ScopeResolutionFailed,
    Tombstoned,
    TracebedError,
)
from tracebed.domain.ids import (
    AgentTypeId,
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    TypedId,
    mint_memory_id,
    mint_run_id,
    uuid7,
    uuid7_timestamp_ms,
)

__all__ = [
    "AbstentionConfig",
    "AgentTypeId",
    "ApiConfig",
    "AuthConfig",
    "AuthenticationFailed",
    "BudgetConfig",
    "BudgetExceeded",
    "CacheConfig",
    "CapExceeded",
    "Clock",
    "ConfigError",
    "ConfigResolver",
    "ConfigStorePort",
    "CrossEpochComparison",
    "DashboardConfig",
    "DerivedConfig",
    "DuplicateRegistration",
    "EffectiveConfig",
    "EmbeddingConfig",
    "EmbeddingTimeout",
    "FakeClock",
    "GuardNotSatisfied",
    "IllegalTransition",
    "KillswitchConfig",
    "LLMProviderConfig",
    "LifecycleConfig",
    "MasterKeyMissing",
    "MemoryId",
    "NotFound",
    "PrincipalId",
    "ProjectId",
    "PromotionConfig",
    "ProposalConfig",
    "ProvenanceIncomplete",
    "QueueConfig",
    "QueueFull",
    "RetirementConfig",
    "RetrievalConfig",
    "RunId",
    "ScanRejected",
    "ScanVerdictForgery",
    "ScopeResolutionFailed",
    "ScoreConfig",
    "ScoringConfig",
    "SessionConfig",
    "SpendConfig",
    "StorageConfig",
    "SystemClock",
    "TierAConfig",
    "Tombstoned",
    "TraceStoreConfig",
    "TracebedError",
    "TracebedSettings",
    "TypedId",
    "mint_memory_id",
    "mint_run_id",
    "uuid7",
    "uuid7_timestamp_ms",
]
