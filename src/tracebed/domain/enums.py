"""Every shared enum in Tracebed (PHASE0-CONTRACT.md §3.2, owner: domain-events-scan).

All `enum.StrEnum`: each member's `.value` IS the wire string AND the DB text
value, so there is exactly one spelling of "human_verdict" in the system.
Changing any value here is a wire-and-schema breaking change — the DDL's
closed-vocabulary columns (`memory_item.mem_type`, `trace_index.arm`,
`trace_index.outcome_status`, `outcome_event.adapter`, ...) are written from
these members and `tests/phase0/test_enums_events.py` pins every value so a
typo cannot pass silently.

Enum ownership (§3.2): `Status` belongs to `domain/state_machine.py` and
`ErrorClassEnum` to `core/scans/tier_a_template.py`. Nothing else defines an
enum another chunk needs.
"""

from __future__ import annotations

from enum import StrEnum


class ProvenanceClass(StrEnum):
    """How a memory item came to exist — the axis invariant 6 validates against.

    `validate_provenance` requires different fields per class, and D-023 makes
    PROPOSAL a class that satisfies no quarantine skip in the state machine.
    """

    PARSER = "parser"
    DISTILLER = "distiller"
    HUMAN_VERDICT = "human_verdict"
    PROPOSAL = "proposal"
    OPERATOR = "operator"


class TrustTier(StrEnum):
    """A = structurally-derived (enters as candidate); B = content-derived
    (enters quarantined, invariant 7)."""

    A = "A"
    B = "B"


class MemType(StrEnum):
    """Memory item kind; also the killswitch overlay's key space (§3.4)."""

    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    LESSON = "lesson"
    PREFERENCE = "preference"


class Lane(StrEnum):
    """Which learning lane produced the item — operational (Tier A parsers)
    or quality (distilled/judged)."""

    OPERATIONAL = "operational"
    QUALITY = "quality"


class ScopeType(StrEnum):
    """The visibility scope of a memory item. NOT project scope — project
    isolation is `ProjectScope`/RLS (invariant 4) and is never expressed here."""

    AGENT_TYPE = "agent_type"
    WORKFLOW_TEMPLATE = "workflow_template"
    USER = "user"
    PROJECT_SHARED = "project_shared"


class Slot(StrEnum):
    """Named slots in a rendered ContextBlock (invariant 3: memory enters
    context only through typed slots, never as free text)."""

    STATIC_PREFIX = "static_prefix"
    FACT = "fact"
    EXEMPLAR = "exemplar"
    PITFALL = "pitfall"
    CANDIDATE_NOTE = "candidate_note"
    JIT_LESSON = "jit_lesson"


class OutcomeCode(StrEnum):
    """Why a retrieval returned what it returned — the observable half of
    invariant 2's degradation ladder, recorded on every `retrieval_event`."""

    INJECTED = "injected"
    ABSTAINED_THRESHOLD = "abstained_threshold"
    ABSTAINED_RARITY = "abstained_rarity"
    EMPTY_RESULT = "empty_result"
    DEGRADED_LEXICAL = "degraded_lexical"
    TIMEOUT_PREFIX_ONLY = "timeout_prefix_only"
    STORE_ERROR = "store_error"
    HOLDOUT = "holdout"


class AdapterClass(StrEnum):
    """Feedback source class. Invariant 8: the server derives the trust weight
    `w` from this class alone — callers never supply a weight, and IMPLICIT
    maps to w=0 (logged, never scored)."""

    VERDICT = "verdict"
    CORRECTION_ADAPTER = "correction_adapter"
    DOWNSTREAM = "downstream"
    IMPLICIT = "implicit"


class Arm(StrEnum):
    """Killswitch experiment arm stamped on every run (`trace_index.arm`)."""

    MEMORY_ON = "memory_on"
    HOLDOUT = "holdout"


class InstrumentationSource(StrEnum):
    """How a trace reached us — needed because completeness guarantees differ
    between SDK-instrumented runs and host stream capture."""

    SDK = "sdk"
    HOST_STREAM = "host_stream"


class TraceOutcomeStatus(StrEnum):
    """`trace_index.outcome_status`. INCOMPLETE is set by the sweeper for runs
    with gaps or no run_end sentinel (D-033) — the distiller refuses those."""

    PENDING = "pending"
    OK = "ok"
    ERROR = "error"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"
