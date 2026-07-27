"""Typed rows returned by `Repo` (PHASE-0 Task 7 / PHASE0-CONTRACT.md §5.2).

This module landed during the parallel build as `stores/pg/models.py`, against §5.2's `rows.py`;
four chunks independently reported the drift. Renamed to the contract's name at integration
(C-28) rather than shimmed, because a re-exporting `models.py` would leave two importable names
for one module and guarantee the next reader picks the wrong one.

These are read-side / write-side row shapes only -- domain types that cross chunk boundaries on
their own (`Provenance`, `NewMemoryItem`, `ProjectScope`, `ScanVerdict`) stay defined once in
`domain/*` (owner: domain-events-scan) and are imported here, never redefined. Duplicating them
in this file, as this chunk's task description independently suggested, would fork the type
across two owners and is exactly what the contract's single-owner-per-symbol rule (§1) forbids;
that suggestion is not followed here and is also logged as a contract_gap.

All frozen/slots (contract convention): these values are read off a `psycopg.Connection` inside
one transaction and must not be mutated afterwards by a caller holding a reference.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from uuid import UUID

from tracebed.domain.enums import (
    AdapterClass,
    Arm,
    InstrumentationSource,
    Lane,
    MemType,
    OutcomeCode,
    ScopeType,
    Slot,
    TraceOutcomeStatus,
    TrustTier,
)
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status

__all__ = [
    "InjectionRow",
    "InvalidationEventRow",
    "KillswitchStateRow",
    "MemoryItemRow",
    "OutcomeEventInsert",
    "PrincipalRow",
    "RetrievalEventInsert",
    "ReviewQueueRow",
    "SpendRow",
    "SubjectKeyRow",
    "TraceIndexRow",
    "TraceIndexUpsert",
]


@dataclass(frozen=True, slots=True)
class PrincipalRow:
    """A `principal` registry row. Returned by `Repo.get_principal_by_external_ref`."""

    principal_id: PrincipalId
    kind: str
    external_ref: str
    key_hash: str | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class MemoryItemRow:
    """A `memory_item` row (contract §5.2). Returned by `Repo.get_memory_by_id`/`list_memories`.

    `provenance` is the parsed `Provenance` (domain/memory.py owns (de)serialisation via
    `Provenance.from_json`), not the raw jsonb -- callers never re-parse it.
    """

    id: MemoryId
    project_id: ProjectId
    scope_type: ScopeType
    scope_id: UUID | None
    mem_type: MemType
    kind: str
    lane: Lane
    trust_tier: TrustTier
    status: Status
    content: str
    content_hash: str
    token_count: int
    subject_tag: str | None
    q_value: float
    confidence: float
    scored_use_count: int
    strike_count: int
    provenance: Provenance
    scan_verdict_id: UUID
    schema_version: int
    created_at: datetime
    status_changed_at: datetime | None


@dataclass(frozen=True, slots=True)
class TraceIndexUpsert:
    """Input to `Repo.upsert_trace_index` (contract §5.2). `ingest.trace_writer` builds one of
    these per batch; optional fields are `None` when that batch doesn't carry the corresponding
    information yet (e.g. no `run_end` seen -> `ended_at=None`, `outcome_status=PENDING`) --
    `Repo` merges partial upserts via `COALESCE` so a later call cannot clobber an earlier one's
    already-known fields with `NULL`.
    """

    run_id: RunId
    agent_type_id: AgentTypeId
    workflow_template_id: UUID | None
    submitter_principal: PrincipalId
    input_signature_hash: bytes
    instrumentation_source: InstrumentationSource
    path: Mapping[str, object] | None
    started_at: datetime | None
    ended_at: datetime | None
    payload_ref: str | None
    outcome_status: TraceOutcomeStatus
    # NO `arm`. `trace_index.arm` is the kill switch's audit column and the stratification key
    # of the governing lift number, and PLAN.md §10 forbids accepting an arm assignment from a
    # caller. It used to arrive here from the caller-supplied `run_start` payload; it is now
    # derived inside `Repo`'s upsert from `retrieval_event.arm` (the server's own record, written
    # by `hotpath.pipeline`). A shape that cannot carry the value cannot smuggle it, which is why
    # this is an absent field rather than an ignored one.


@dataclass(frozen=True, slots=True)
class TraceIndexRow:
    """A `trace_index` row as actually stored -- same shape as `TraceIndexUpsert` plus
    `project_id` (contract §5.2: "same fields, all concrete, plus project_id").
    """

    project_id: ProjectId
    run_id: RunId
    agent_type_id: AgentTypeId
    workflow_template_id: UUID | None
    submitter_principal: PrincipalId
    input_signature_hash: bytes
    instrumentation_source: InstrumentationSource
    arm: Arm
    path: Mapping[str, object] | None
    started_at: datetime | None
    ended_at: datetime | None
    payload_ref: str | None
    outcome_status: TraceOutcomeStatus


@dataclass(frozen=True, slots=True)
class OutcomeEventInsert:
    """Input to `Repo.insert_outcome_event` (contract §5.2). `w_zero` is never stored as its own
    column (`r`/`w` are server-derived, never caller data, PLAN.md §2 invariant 8) -- `Repo`
    folds it into `payload["_w_zero"]` per C-10.
    """

    event_id: UUID
    run_id: RunId
    principal_id: PrincipalId
    adapter: AdapterClass
    r: float
    w_zero: bool
    payload: Mapping[str, object]
    occurred_at: datetime
    arrived_at: datetime


@dataclass(frozen=True, slots=True)
class RetrievalEventInsert:
    """Input to `Repo.insert_retrieval_event` (contract §5.2)."""

    run_id: RunId
    outcome_code: OutcomeCode
    latency_ms: int
    embed_latency_ms: int | None
    candidates_considered: int
    top_score: float | None
    arm: Arm


@dataclass(frozen=True, slots=True)
class InjectionRow:
    """One `injection_log` row; input to `Repo.insert_injection_rows` (contract §5.2)."""

    memory_id: MemoryId
    slot: Slot
    score: float
    tokens: int


@dataclass(frozen=True, slots=True)
class SubjectKeyRow:
    """A `subject_key` row (contract §5.2). `crypto.shred.SubjectKeyManager` is the only reader
    that interprets `wrapped_kek`; `Repo` treats it as opaque bytes.
    """

    subject_tag: str
    key_id: UUID
    wrapped_kek: bytes
    created_at: datetime
    destroyed_at: datetime | None


@dataclass(frozen=True, slots=True)
class SpendRow:
    """One `spend_ledger` row for a (day, worker, model_id) cell (contract §5.2)."""

    day: date
    worker: str
    model_id: str
    tokens_in: int
    tokens_out: int
    cost_usd: float


# --------------------------------------------------------------------------- #
# Control-plane read rows (D-093). Added so the dashboard's governance views
# read the real tables instead of a fixture: every one of these tables was
# already WRITTEN by some worker or route and had no reader anywhere, which is
# the state that produced four fabricated dashboard views.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ReviewQueueRow:
    """One `review_queue` row (migrations/0002). `resolved_at is None` is the
    open case — the only case an operator has to act on."""

    item_id: UUID
    reason: str
    memory_id: MemoryId | None
    opened_at: datetime
    resolved_at: datetime | None
    resolution: str | None


@dataclass(frozen=True, slots=True)
class KillswitchStateRow:
    """One `killswitch_state` cell (migrations/0001).

    `agent_type_id is None` is the project-wide overlay row, not a missing
    value — the migration's own comment calls it the sentinel, and a reader
    that rendered it as "unknown agent type" would misreport the widest
    possible disablement as the narrowest.

    `evidence` is the worker's own decision record (`workers/killswitch.py`
    `_evidence`): it carries `source`, `reason`, the measured lift and its
    bounds. It is returned verbatim rather than reshaped, because the shape is
    the worker's to define and a reader that re-derived it would be a second
    source of truth for a governing decision.
    """

    agent_type_id: AgentTypeId | None
    mem_type: MemType
    disabled: bool
    evidence: Mapping[str, object] | None
    changed_at: datetime


@dataclass(frozen=True, slots=True)
class InvalidationEventRow:
    """One `invalidation_event` row (migrations/0002) — written by
    `POST /v1/invalidation`, read by nothing until D-093."""

    event_id: UUID
    event_type: str
    selector: Mapping[str, object] | None
    fired_at: datetime
