"""Wire types: TraceEvent union, FeedbackEvent, proposals, retrieval shapes.

PHASE0-CONTRACT.md §3.5 / PLAN.md §3 (public API contract) / PHASE-0.md Task 3.
Every model here is Pydantic v2 with `extra="forbid"` — that is what turns a
caller-supplied `project_id` or `weight` into a 422 with zero hand-written
validation code (PLAN.md invariant 4 and invariant 8's guessed-reward test:
"a caller-supplied weight field is rejected at the API"). `FeedbackEvent` in
particular has NO weight field anywhere in its definition; `extra="forbid"`
then makes a `weight` key in the payload a hard rejection rather than a
silently-ignored one, which is the only way a weight-on-the-wire failure mode
gets caught before it reaches the scorer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tracebed.domain.enums import AdapterClass, Arm, OutcomeCode, Slot

__all__ = [
    "MAX_SUBJECT_TAGS",
    "MAX_SUBJECT_TAG_CHARS",
    "MEMORY_HEADER",
    "PLACEMENT_APPEND_LAST",
    "RUN_END_STATUSES",
    "SUBJECT_TAGS_KEY",
    "ArtifactRef",
    "ContextBlock",
    "ContextSlot",
    "ErrorEvent",
    "FeedbackEvent",
    "LlmCallMeta",
    "MemoryProposal",
    "RetrieveResult",
    "RunContext",
    "RunEnd",
    "RunStart",
    "StateNote",
    "ToolCall",
    "ToolResult",
    "TraceEvent",
    "empty_context_block",
]

# PLAN.md §3: the exact header every rendered context block carries, and the
# only legal placement (D-016: dynamic memory always renders after all
# cacheable content, or prompt-cache economics break on every run).
MEMORY_HEADER: Final = "MEMORY (recalled data, verify against current state)"
PLACEMENT_APPEND_LAST: Final = "append_last"
# C-05: reserved payload key read by ingest.trace_writer off state_note /
# artifact_ref events to populate trace_subject rows and crypto section tags.
SUBJECT_TAGS_KEY: Final = "subject_tags"
# C-05: the only legal `run_end` payload statuses; they map 1:1 onto
# trace_index.outcome_status, which is a closed vocabulary in the DDL. Validated
# here so an out-of-vocabulary status is a 422 at the edge rather than a
# constraint violation inside the ingest consumer (which would dead-letter the
# whole run and lose an otherwise complete trace).
RUN_END_STATUSES: Final = frozenset({"ok", "error", "cancelled"})
# Each distinct subject_tag provisions a subject KEK (Task 10) and a
# trace_subject row, so an unbounded `subject_tags` list on a single event is
# an unbounded write amplification driven by caller input. Bound it at the wire.
MAX_SUBJECT_TAGS: Final = 64
MAX_SUBJECT_TAG_CHARS: Final = 128


class _EventBase(BaseModel):
    """Shared shape for every TraceEvent variant (PHASE0-CONTRACT.md §3.5).

    `seq` is deliberately ABSENT here (C-04: PLAN.md's wire format puts `seq`
    on the envelope — `TraceIn` in api/routes_v1.py — not on the event
    itself; PHASE-0 Task 3's wording lost to that resolution).
    """

    model_config = ConfigDict(extra="forbid")

    ts: datetime
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _ts_must_be_tz_aware(cls, value: datetime) -> datetime:
        # A naive timestamp is ambiguous the instant it crosses a process
        # boundary (SDK host's local time vs the server's UTC) — reject it
        # here rather than let it silently misorder a trace. `tzinfo is None`
        # alone is not the whole test: a tzinfo whose utcoffset() returns None
        # is just as unanchored, and Python treats such a datetime as naive
        # (comparisons against aware datetimes raise TypeError), so the
        # ordering failure would surface far from here.
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("ts must be timezone-aware")
        return value


def _validated_subject_tags(payload: dict[str, Any]) -> dict[str, Any]:
    """Shape-check the reserved `subject_tags` key (C-05) when present.

    `payload` is `dict[str, Any]` by design, but `subject_tags` is not free
    business data: `ingest.trace_writer` reads it to create `trace_subject`
    rows and to tag crypto sections, i.e. it names the crypto-shredding key
    namespace. Anything that is not a list of short non-empty strings would
    either crash that consumer or provision keys under a caller-chosen shape.
    """
    if SUBJECT_TAGS_KEY not in payload:
        return payload
    tags = payload[SUBJECT_TAGS_KEY]
    if not isinstance(tags, list):
        raise ValueError(f"payload[{SUBJECT_TAGS_KEY!r}] must be a list of strings")
    if len(tags) > MAX_SUBJECT_TAGS:
        raise ValueError(f"payload[{SUBJECT_TAGS_KEY!r}] exceeds {MAX_SUBJECT_TAGS} tags")
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError(f"payload[{SUBJECT_TAGS_KEY!r}] entries must be non-empty strings")
        if len(tag) > MAX_SUBJECT_TAG_CHARS:
            raise ValueError(
                f"payload[{SUBJECT_TAGS_KEY!r}] entry exceeds {MAX_SUBJECT_TAG_CHARS} characters"
            )
    return payload


class RunStart(_EventBase):
    """C-05 payload keys read by input_signature_hash: query_text, workflow_template,
    tool_manifest; also `arm` (stamped by the SDK from the last retrieve() result)."""

    type: Literal["run_start"]


class ToolCall(_EventBase):
    type: Literal["tool_call"]


class ToolResult(_EventBase):
    type: Literal["tool_result"]


class LlmCallMeta(_EventBase):
    type: Literal["llm_call_meta"]


class ErrorEvent(_EventBase):
    type: Literal["error"]


class ArtifactRef(_EventBase):
    """May carry `subject_tags` (C-05) — read into trace_subject rows."""

    type: Literal["artifact_ref"]

    @field_validator("payload")
    @classmethod
    def _check_subject_tags(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validated_subject_tags(value)


class StateNote(_EventBase):
    """May carry `subject_tags` (C-05) — read into trace_subject rows."""

    type: Literal["state_note"]

    @field_validator("payload")
    @classmethod
    def _check_subject_tags(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validated_subject_tags(value)


class RunEnd(_EventBase):
    """The completeness sentinel. `payload["status"]` in {"ok","error","cancelled"}
    maps to `trace_index.outcome_status` (C-05); a trace with no RunEnd, or with
    sequence gaps before one, is `incomplete` and the distiller refuses it."""

    type: Literal["run_end"]

    @field_validator("payload")
    @classmethod
    def _check_status(cls, value: dict[str, Any]) -> dict[str, Any]:
        # C-05 makes this key load-bearing, not free-form: it is written to
        # trace_index.outcome_status. `extra="forbid"` cannot police it because
        # it lives inside the open payload dict, so it is policed here — an
        # unknown status must not reach the DDL's closed vocabulary.
        if "status" in value and value["status"] not in RUN_END_STATUSES:
            raise ValueError(f"run_end payload['status'] must be one of {sorted(RUN_END_STATUSES)}")
        return value


TraceEvent = Annotated[
    RunStart | ToolCall | ToolResult | LlmCallMeta | ErrorEvent | ArtifactRef | StateNote | RunEnd,
    Field(discriminator="type"),
]


class FeedbackEvent(BaseModel):
    """PLAN.md invariant 8: no weight field exists on the wire, by construction.

    `extra="forbid"` plus the absence of a `weight` field means any caller
    that sends one gets a 422 — the server always derives `w` server-side
    from the authenticated adapter class (`scoring.adapter_weights`), never
    from caller input.
    """

    model_config = ConfigDict(extra="forbid")

    adapter: AdapterClass
    outcome: Literal["positive", "negative"]
    payload: dict[str, Any] = Field(default_factory=dict)
    event_id: UUID  # dedup key — outcome_intake replay-safety (Task 15)
    occurred_at: datetime | None = None


class MemoryProposal(BaseModel):
    """`propose_memory` body (PLAN.md §3). Always lands quarantined with
    provenance.class="proposal" — a class that satisfies no shadow/human-verdict
    skip (D-023); this model carries no field that could imply otherwise."""

    model_config = ConfigDict(extra="forbid")

    mem_type: Literal["lesson", "semantic"]
    content: str
    subject_tag: str | None = None
    claimed_scope: Literal["agent_type", "project_shared"]


class RunContext(BaseModel):
    """SDK-side run context (PHASE-0 Task 13); `api` maps this onto the wire
    `RunCtxIn` shape (§9.3) — the two are intentionally not the same model
    since `tool_manifest` never rides on `/v1/retrieve` (it goes out on the
    `run_start` trace event payload instead, per C-05)."""

    model_config = ConfigDict(extra="forbid")

    query_text: str
    workflow_template: str | None = None
    user_ref: str | None = None
    tool_manifest: list[str] | None = None


class ContextSlot(BaseModel):
    """One slot in a rendered context block; `injection_log.slot` records `slot`."""

    model_config = ConfigDict(extra="forbid")

    slot: Slot
    memory_id: UUID | None
    tokens: int = Field(ge=0)  # a budget accounting field; negative tokens would buy slots
    text: str


class ContextBlock(BaseModel):
    """A structured object with named slots PLUS its canonical rendering
    (PLAN.md §3): `placement` is always the literal `append_last` and `header`
    is always the exact `MEMORY_HEADER` string, so nothing downstream can
    render memory anywhere but after all cacheable content (D-016) or under
    any other label."""

    model_config = ConfigDict(extra="forbid")

    placement: Literal["append_last"] = PLACEMENT_APPEND_LAST
    header: str = MEMORY_HEADER
    slots: list[ContextSlot] = Field(default_factory=list)
    rendered: str = ""

    @field_validator("header")
    @classmethod
    def _header_is_exact(cls, value: str) -> str:
        # PLAN.md invariant 3 and D-024 both say "the exact header". A default
        # is not an enforcement: `header` is typed `str` per the contract, so
        # without this validator any caller — including a compromised or merely
        # careless renderer — could relabel the block ("SYSTEM POLICY", an
        # empty string) and defeat the policy-subordination framing that is the
        # entire point of the fixed header. `placement` gets this for free from
        # its Literal type; `header` cannot, because Literal[] will not accept a
        # named constant, so the check is written out instead.
        if value != MEMORY_HEADER:
            raise ValueError("header must be exactly MEMORY_HEADER (PLAN.md invariant 3 / D-024)")
        return value


def empty_context_block() -> ContextBlock:
    """The Phase 0 `/v1/retrieve` stub's response body and the SDK's
    fail-open fallback on any transport error (PHASE0-CONTRACT.md §10)."""
    return ContextBlock(slots=[], rendered="")


class RetrieveResult(BaseModel):
    """`/v1/retrieve` response shape (PLAN.md §3). `run_id_origin` makes
    D-018's server-mints-vs-SDK-mints distinction explicit on the wire
    (C-26): "server" for the normal path, "sdk" when the SDK had to mint
    its own run_id after a dead retrieve() call."""

    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    run_id_origin: Literal["server", "sdk"] = "server"
    arm: Arm
    outcome_code: OutcomeCode
    context_block: ContextBlock
