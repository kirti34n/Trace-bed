"""Wire request/response models for the SDK-facing and admin routes.

PHASE0-CONTRACT.md §9.3. Every model is `extra="forbid"` — that, plus the
absence of a `project_id` field on any non-admin model and the absence of a
`weight` field on `FeedbackEvent` (domain/events.py), is what turns a
caller-supplied `project_id` or `weight` into a 422 with zero hand-written
validation code (invariants 4 and 8).

PHASE0-CONTRACT.md's §9.3 sketches these wire models as living directly inside
`api/routes_v1.py`; they live here instead so `api/admin.py`'s bodies (which the
contract sketch gives no home to) share one import surface rather than being
split or duplicated. §1 gained a row for this module at integration (C-28).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tracebed.domain.events import FeedbackEvent, MemoryProposal, TraceEvent

__all__ = [
    "MAX_NAME_CHARS",
    "MAX_QUERY_TEXT_CHARS",
    "MAX_SEQ",
    "MAX_TRACE_BATCH_EVENTS",
    "AcceptedOut",
    "AgentPrincipalIn",
    "AgentRegisteredOut",
    "ApiKeyPrincipalIn",
    "ConfigOut",
    "FeedbackIn",
    "InvalidationEventOut",
    "InvalidationIn",
    "InvalidationListOut",
    "KillswitchCellOut",
    "KillswitchStateOut",
    "MemoryItemOut",
    "MemoryListOut",
    "OidcPrincipalIn",
    "ProjectCreateIn",
    "ProjectCreatedOut",
    "ProposeIn",
    "RegisterAgentIn",
    "RetrieveIn",
    "ReviewItemOut",
    "ReviewQueueOut",
    "RunCtxIn",
    "ScopeOut",
    "SpendCellOut",
    "SpendOut",
    "TraceBatchIn",
    "TraceIn",
]

# C-21: the SDK flusher's batch endpoint caps at 500 events per call.
MAX_TRACE_BATCH_EVENTS = 500
# Every free-text field a caller controls gets a ceiling at the wire, for the
# same reason `domain/events.py` bounds `subject_tags`: an unbounded string is
# an unbounded allocation (and, from Phase 1, an unbounded embedding call)
# driven entirely by request input, on routes that authenticate but do not
# otherwise rate-limit.
MAX_QUERY_TEXT_CHARS = 32_768
MAX_NAME_CHARS = 256
# `seq` is a per-run counter starting at 0 (C-23) and lands in a jsonb queue
# envelope. Deliberately the SAME ceiling as `ingest.trace_writer.MAX_TRACE_SEQ`
# (C-33): a seq above it is refused by the ingest consumer, so accepting one
# here means answering 202 "accepted" and dead-lettering the event later, out of
# the caller's sight. Rejecting at the wire makes it a 422 the caller can act on.
# The value is mirrored rather than imported because `api` must not depend on
# `ingest` (§14 keeps the request plane and the consumer plane apart);
# `tests/phase0/test_integration_seams.py` asserts the two constants agree, so
# they cannot drift silently.
MAX_SEQ = 1_000_000


# --------------------------------------------------------------------------- #
# /v1/* request bodies (contract §9.3). Every model forbids extra keys and,
# critically, declares no `project_id` field anywhere — scope is derived
# server-side from the authenticated principal (invariant 4), never accepted
# from a caller on a data route.
# --------------------------------------------------------------------------- #


class RunCtxIn(BaseModel):
    """PLAN.md §3's retrieve `run_ctx` object."""

    model_config = ConfigDict(extra="forbid")

    query_text: str = Field(max_length=MAX_QUERY_TEXT_CHARS)
    workflow_template: str | None = Field(default=None, max_length=MAX_NAME_CHARS)
    user_ref: str | None = Field(default=None, max_length=MAX_NAME_CHARS)
    session_id: str | None = Field(default=None, max_length=MAX_NAME_CHARS)
    prefetch_for: str | None = Field(default=None, max_length=MAX_NAME_CHARS)


class RetrieveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_type: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    run_ctx: RunCtxIn


class TraceIn(BaseModel):
    """One trace-event envelope. `seq` lives here, not on `TraceEvent` itself
    (C-04: PLAN.md's wire format puts `seq` on the envelope)."""

    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    seq: int = Field(ge=0, le=MAX_SEQ)
    event: TraceEvent


class TraceBatchIn(BaseModel):
    """The SDK flusher's endpoint (C-21); single-event `/v1/trace` is kept too."""

    model_config = ConfigDict(extra="forbid")

    events: Annotated[list[TraceIn], Field(max_length=MAX_TRACE_BATCH_EVENTS)]


class FeedbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    event: FeedbackEvent

    @field_validator("event")
    @classmethod
    def _occurred_at_must_be_aware(cls, event: FeedbackEvent) -> FeedbackEvent:
        """C-35. `outcome_event.occurred_at` is `timestamptz`; Postgres reinterprets a naive
        value in the session's TimeZone, so the event silently moves by hours with no
        downstream way to detect it — and T+2-day feedback attach is a time join.

        `domain.events._EventBase.ts` already rejects naive timestamps, but `FeedbackEvent`
        (a separate base) does not, and `domain/` is frozen. `ingest.outcome_intake` refuses a
        naive value too, but only after this route has returned 202 — the caller never learns.
        Rejecting here makes it a 422 the caller can act on, and leaves the consumer's refusal
        in place for envelopes that arrive from a replay tool rather than this route.
        """
        if event.occurred_at is not None and event.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware (the column is timestamptz)")
        return event


class ProposeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: UUID
    proposal: MemoryProposal


class InvalidationIn(BaseModel):
    """`POST /v1/invalidation` body (C-31).

    `kind` lands in `invalidation_event.event_type` and `payload` in its
    `selector` jsonb. Neither names a project: scope comes from the
    authenticated principal like every other `/v1/*` route.

    PHASE0-CONTRACT.md §9.3's route table does not list this route (PLAN.md §3
    does, and PLAN.md §5 defines the table it writes to), so its wire shape is
    fixed here at integration rather than inherited. `payload` is bounded only
    by the ASGI server's body limit — a jsonb selector has no natural per-key
    schema in Phase 0, and inventing one would reject real webhook shapes.
    """

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    payload: dict[str, Any] = Field(default_factory=dict)


class AcceptedOut(BaseModel):
    """The uniform 202 body for every enqueue-only route (contract §9.3)."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["accepted"] = "accepted"


# --------------------------------------------------------------------------- #
# Admin / registry bodies (contract §9.3). These, and ONLY these, may name
# `project_id` — the admin is naming the project being provisioned, which is
# the registry write path, not a data route (§14 api-auth DO-NOT list).
# --------------------------------------------------------------------------- #


class ProjectCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    retention_policy: dict[str, Any] | None = None


class ProjectCreatedOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID


class OidcPrincipalIn(BaseModel):
    """`{"kind": "oidc_sub", "sub": ...}` — the IdP-controlled subject that
    `OidcJwksVerifier` will later match a token's `sub` against."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["oidc_sub"]
    sub: str = Field(min_length=1, max_length=MAX_NAME_CHARS)


class ApiKeyPrincipalIn(BaseModel):
    """`{"kind": "api_key"}` — carries no `sub`, and `extra="forbid"` is what
    rejects one: an `external_ref` for an api_key principal is the server-
    minted key_id (C-19) and must never be caller-chosen, because a caller who
    could pick it could aim it at an existing principal's row."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["api_key"]


# A discriminated union rather than one optional-`sub` model: it makes
# "oidc_sub without a sub" unrepresentable in the parsed type, so `admin.py`
# needs no runtime `assert` (which `python -O` strips) to hand a non-None
# external_ref to the registry. Pydantic tags errors by the `kind` value, so
# the 422 still names the offending field rather than "no matching variant".
AgentPrincipalIn = Annotated[
    OidcPrincipalIn | ApiKeyPrincipalIn, Field(discriminator="kind")
]


class RegisterAgentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    agent_type: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    principal: AgentPrincipalIn


class AgentRegisteredOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: UUID
    agent_type_id: UUID
    api_key: str | None = None
    """The ONE-TIME plaintext `tb_sk_<key_id>.<secret>` — present only when
    `principal.kind == "api_key"`; never recoverable after this response."""


class MemoryItemOut(BaseModel):
    """`GET /admin/memory/{memory_id}` response — a JSON-safe projection of
    `stores.pg.rows.MemoryItemRow` (UUIDs/datetimes as strings, `Provenance`
    via its own `to_json()`), built explicitly rather than via
    `model_validate` because `MemoryItemRow` is a frozen dataclass holding
    domain newtypes and enums that are not themselves JSON-encodable."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    scope_type: str
    scope_id: str | None
    mem_type: str
    kind: str
    lane: str
    trust_tier: str
    status: str
    content: str
    content_hash: str
    token_count: int
    subject_tag: str | None
    q_value: float
    confidence: float
    scored_use_count: int
    strike_count: int
    provenance: dict[str, Any]
    scan_verdict_id: str
    schema_version: int
    created_at: str
    status_changed_at: str | None


# --------------------------------------------------------------------------- #
# Control-plane read bodies (D-093). Every one is project-scoped by the same
# `ScopeDep` the rest of the read plane uses, so none of them names a
# `project_id` in a REQUEST — `MemoryScopeOut` reports the resolved scope back
# to the caller, which is the opposite direction and the reason the dashboard
# can stop guessing which project its credential lands in.
# --------------------------------------------------------------------------- #


class ScopeOut(BaseModel):
    """`GET /admin/whoami` — the scope the server derived for this credential.

    Reporting a project id is not the same as accepting one (invariant 4): the
    value here is the OUTPUT of `Repo.resolve_project`, and a caller sending it
    back on any other route is still a 422.
    """

    model_config = ConfigDict(extra="forbid")

    project_id: str
    agent_type_id: str
    principal_id: str


class MemoryListOut(BaseModel):
    """`GET /admin/memory` — a bounded page of `memory_item` rows.

    `limit` and `returned` are both present on purpose: `returned == limit` is
    the only signal a caller has that the vault is larger than what it got, and
    a list route that reported neither would let a dashboard present a truncated
    count as a total (which is what the export-backed views had to work around).
    """

    model_config = ConfigDict(extra="forbid")

    items: list[MemoryItemOut]
    limit: int
    returned: int


class ReviewItemOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str
    reason: str
    memory_id: str | None
    opened_at: str
    resolved_at: str | None
    resolution: str | None


class ReviewQueueOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ReviewItemOut]
    limit: int
    returned: int
    include_resolved: bool


class KillswitchCellOut(BaseModel):
    """One `killswitch_state` cell. `agent_type_id: None` is the project-wide
    overlay, not an unknown agent type (migrations/0001's own sentinel note).

    `evidence` is passed through verbatim from whatever wrote the row
    (`workers/killswitch.py`), never re-derived here: a governing decision has
    exactly one author, and a route that reshaped its evidence would become a
    second one.
    """

    model_config = ConfigDict(extra="forbid")

    agent_type_id: str | None
    mem_type: str
    disabled: bool
    evidence: dict[str, Any] | None
    changed_at: str


class KillswitchStateOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cells: list[KillswitchCellOut]


class InvalidationEventOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    selector: dict[str, Any] | None
    fired_at: str


class InvalidationListOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[InvalidationEventOut]
    limit: int
    returned: int


class SpendCellOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    day: str
    worker: str
    model_id: str
    tokens_in: int
    tokens_out: int
    cost_usd: float


class SpendOut(BaseModel):
    """`GET /admin/spend`. `since` and `days` travel with the rows so a total
    can never be rendered without the window it was computed over."""

    model_config = ConfigDict(extra="forbid")

    since: str
    days: int
    cells: list[SpendCellOut]


class ConfigOut(BaseModel):
    """`GET /admin/config` — the two STORED override layers only.

    PLAN.md §6's resolution order is process defaults -> `project_config` ->
    `agent_type_config` -> killswitch overlay. Only the middle two are rows in
    this project's own tables; the process defaults live in the server's
    environment and the overlay has its own route. Returning just the overrides,
    labelled as overrides, is why the dashboard can say "this key is overridden
    for this agent type" without claiming to know the resolved value.
    """

    model_config = ConfigDict(extra="forbid")

    agent_type_id: str
    project: dict[str, Any]
    agent_type: dict[str, Any]
