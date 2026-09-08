"""Every Protocol that crosses a chunk boundary (PHASE0-CONTRACT.md §8).

Protocols only — zero implementations, zero I/O. Concrete classes satisfy these
structurally; nothing inherits from them. That is what lets `api`, `ingest` and
`sdk` be tested offline against fakes on a machine with no Postgres, no Valkey
and no object store.

Two import rules keep this file honest, and both are enforced by CI:

  - It must not import `tracebed.crypto`. `scripts/purity_check.py` walks the
    hot path's import graph, and `hotpath` imports `adapters.ports`; a crypto
    edge here would drag trace-payload encryption into the hot read path.
    That is why `SubjectKeyStore` and `ConfigStorePort` stay defined beside
    their consumers instead of being centralised here (C-18).
  - It must not import a provider SDK. A generative client reachable from the
    hot path fails invariant 1 outright.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Literal, Protocol, runtime_checkable
from uuid import UUID

from pydantic import TypeAdapter

from tracebed.domain.authority import AccessContext
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.enums import Arm, OutcomeCode
from tracebed.domain.events import MAX_TRACE_SEQ, MemoryProposal, TraceEvent
from tracebed.domain.ids import PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.stores.tracestore import TraceStorePort

if TYPE_CHECKING:
    # Imported for typing only: `identity` lands with the api-auth chunk, and a
    # runtime import here would make ports.py depend on the API layer it serves.
    from tracebed.adapters.identity import Principal
    from tracebed.domain.events import FeedbackEvent
    from tracebed.stores.pg.queue import QueueItem

__all__ = [
    "AccessResolverPort",
    "AuditSinkPort",
    "AuthorizedQueueProducerPort",
    "AuthorizedQueueWrite",
    "EmbeddingPort",
    "FeedbackPort",
    "InvalidationPort",
    "LLMProviderPort",
    "OutcomeQueuePayload",
    "PrincipalPort",
    "ProjectResolverPort",
    "ProposalQueuePayload",
    "QueueConsumerPort",
    "QueueProducerPort",
    "TelemetryPort",
    "TraceQueuePayload",
    "TraceStorePort",
    "WorkerQueueConsumerPort",
]


_MAX_AUTHORIZED_QUEUE_TOPIC_CHARS: Final = 256
_MAX_AUTHORIZED_QUEUE_PAYLOAD_DEPTH: Final = 16
_MAX_AUTHORIZED_QUEUE_PAYLOAD_NODES: Final = 2_048
_MAX_AUTHORIZED_QUEUE_PAYLOAD_KEY_CHARS: Final = 256
_MAX_AUTHORIZED_QUEUE_PAYLOAD_STRING_CHARS: Final = 32_768
# A portable JSON carrier must not rely on Python's unbounded ``int`` or a
# particular JSONB numeric implementation.  This is a wire-portability bound,
# not a business-column constraint.
_MIN_AUTHORIZED_QUEUE_JSON_INT: Final = -(2**63)
_MAX_AUTHORIZED_QUEUE_JSON_INT: Final = 2**63 - 1
_PG_INTEGER_MIN: Final = -(2**31)
_PG_INTEGER_MAX: Final = 2**31 - 1
_TRACE_EVENT_TOPIC: Final = "trace_event"
_OUTCOME_EVENT_TOPIC: Final = "outcome_event"
_MEMORY_PROPOSAL_TOPIC: Final = "memory_proposal"
_TRACE_EVENT_ADAPTER: Final[TypeAdapter[TraceEvent]] = TypeAdapter(TraceEvent)
_MEMORY_PROPOSAL_ADAPTER: Final[TypeAdapter[MemoryProposal]] = TypeAdapter(MemoryProposal)


def _freeze_json_value(
    value: object,
    *,
    depth: int,
    nodes: list[int],
    ancestors: set[int],
) -> object:
    """Validate bounded JSON-shaped business data and detach mutable inputs.

    These values are intentionally *business opaque*: the typed carrier owns
    its control fields, while a trace event's ``payload`` or an outcome's
    metrics may legitimately use names such as ``status`` or ``adapter``.
    Authority is therefore not inferred from arbitrary JSON keys.
    """

    if depth > _MAX_AUTHORIZED_QUEUE_PAYLOAD_DEPTH:
        raise ValueError("authorized queue payload is nested too deeply")
    nodes[0] += 1
    if nodes[0] > _MAX_AUTHORIZED_QUEUE_PAYLOAD_NODES:
        raise ValueError("authorized queue payload has too many values")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not _MIN_AUTHORIZED_QUEUE_JSON_INT <= value <= _MAX_AUTHORIZED_QUEUE_JSON_INT:
            raise ValueError("authorized queue payload integer is outside the portable range")
        return value
    if type(value) is str:
        _validate_json_string(
            value,
            max_chars=_MAX_AUTHORIZED_QUEUE_PAYLOAD_STRING_CHARS,
            message="authorized queue payload string is invalid",
        )
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("authorized queue payload floats must be finite")
        return value
    if isinstance(value, Mapping):
        value_id = id(value)
        if value_id in ancestors:
            raise ValueError("authorized queue payload must not be cyclic")
        ancestors.add(value_id)
        frozen: dict[str, object] = {}
        try:
            for key, item in value.items():
                if type(key) is not str or not key:
                    raise TypeError("authorized queue payload keys must be non-empty strings")
                _validate_json_string(
                    key,
                    max_chars=_MAX_AUTHORIZED_QUEUE_PAYLOAD_KEY_CHARS,
                    message="authorized queue payload key is invalid",
                )
                frozen[key] = _freeze_json_value(
                    item,
                    depth=depth + 1,
                    nodes=nodes,
                    ancestors=ancestors,
                )
        finally:
            ancestors.remove(value_id)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        value_id = id(value)
        if value_id in ancestors:
            raise ValueError("authorized queue payload must not be cyclic")
        ancestors.add(value_id)
        try:
            return tuple(
                _freeze_json_value(
                    item,
                    depth=depth + 1,
                    nodes=nodes,
                    ancestors=ancestors,
                )
                for item in value
            )
        finally:
            ancestors.remove(value_id)
    raise TypeError(f"authorized queue payload has unsupported {type(value).__name__} value")


def _validate_json_string(value: str, *, max_chars: int, message: str) -> None:
    """Reject strings that cannot be safely carried by portable JSON codecs."""

    if "\x00" in value:
        raise ValueError(message)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ValueError(message) from None
    if len(value) > max_chars or len(encoded) > max_chars:
        raise ValueError(message)


def _freeze_json_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    frozen = _freeze_json_value(value, depth=0, nodes=[0], ancestors=set())
    if not isinstance(frozen, Mapping):  # pragma: no cover - checked by callers
        raise TypeError("payload must be a mapping")
    return frozen


def _thaw_json_value(value: object) -> object:
    """Return a detached ordinary JSON container from validated frozen data."""

    if isinstance(value, Mapping):
        return {key: _thaw_json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json_value(item) for item in value]
    return value


def _thaw_json_mapping(value: Mapping[str, object]) -> dict[str, object]:
    thawed = _thaw_json_value(value)
    if not isinstance(thawed, dict):  # pragma: no cover - callers always pass mappings
        raise TypeError("payload must be a mapping")
    return thawed


def _event_wire_mapping(event: TraceEvent) -> Mapping[str, object]:
    dumped = event.model_dump(mode="json")
    return _freeze_json_mapping(dumped)


def _proposal_wire_mapping(proposal: MemoryProposal) -> Mapping[str, object]:
    dumped = proposal.model_dump(mode="json")
    return _freeze_json_mapping(dumped)


@dataclass(frozen=True, slots=True)
class TraceQueuePayload:
    """The only business shape accepted for ``trace_event`` queue writes."""

    seq: int
    event: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.seq) is not int:
            raise TypeError("seq must be an int")
        if not 0 <= self.seq <= MAX_TRACE_SEQ:
            raise ValueError("seq is outside the supported trace range")
        if not isinstance(self.event, Mapping):
            raise TypeError("event must be a mapping")
        # Validate the opaque event payload *before* Pydantic sees it.  The
        # event models deliberately allow arbitrary business JSON inside
        # ``payload``; model coercion must not stringify a UUID, consume a
        # generator, or turn another non-JSON object into accepted wire data.
        raw_event = dict(self.event)
        raw_payload = raw_event.get("payload")
        if not isinstance(raw_payload, Mapping):
            raise TypeError("event payload must be a mapping")
        frozen_payload = _freeze_json_mapping(raw_payload)
        raw_event["payload"] = _thaw_json_mapping(frozen_payload)
        parsed = _TRACE_EVENT_ADAPTER.validate_python(raw_event)
        object.__setattr__(self, "event", _event_wire_mapping(parsed))

    def as_mapping(self) -> Mapping[str, object]:
        return MappingProxyType({"seq": self.seq, "event": self.event})

    def to_json_mapping(self) -> dict[str, object]:
        return _thaw_json_mapping(self.as_mapping())


@dataclass(frozen=True, slots=True)
class OutcomeQueuePayload:
    """The only business shape accepted for ``outcome_event`` queue writes.

    ``payload`` is opaque metrics/business context.  It cannot become an
    authority channel because trust fields are absent from this carrier's
    typed control plane and future consumers must derive authority separately.
    """

    event_id: UUID
    outcome: Literal["positive", "negative"]
    payload: Mapping[str, object]
    occurred_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.event_id) is not UUID:
            raise TypeError("event_id must be a UUID")
        raw_outcome: object = self.outcome
        if type(raw_outcome) is not str or raw_outcome not in {"positive", "negative"}:
            raise ValueError("outcome must be positive or negative")
        if not isinstance(self.payload, Mapping):
            raise TypeError("payload must be a mapping")
        if self.occurred_at is not None:
            if type(self.occurred_at) is not datetime:
                raise TypeError("occurred_at must be a datetime or None")
            if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
                raise ValueError("occurred_at must be timezone-aware")
        object.__setattr__(self, "payload", _freeze_json_mapping(self.payload))

    def as_mapping(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "event_id": str(self.event_id),
                "outcome": self.outcome,
                "payload": self.payload,
                "occurred_at": self.occurred_at.isoformat()
                if self.occurred_at is not None
                else None,
            }
        )

    def to_json_mapping(self) -> dict[str, object]:
        return _thaw_json_mapping(self.as_mapping())


@dataclass(frozen=True, slots=True)
class ProposalQueuePayload:
    """The only business shape accepted for ``memory_proposal`` queue writes."""

    proposal: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.proposal, Mapping):
            raise TypeError("proposal must be a mapping")
        parsed = _MEMORY_PROPOSAL_ADAPTER.validate_python(dict(self.proposal))
        object.__setattr__(self, "proposal", _proposal_wire_mapping(parsed))

    def as_mapping(self) -> Mapping[str, object]:
        return MappingProxyType({"proposal": self.proposal})

    def to_json_mapping(self) -> dict[str, object]:
        return _thaw_json_mapping(self.as_mapping())


@dataclass(frozen=True, slots=True)
class AuthorizedQueueWrite:
    """An immutable business write whose project authority comes from ``AccessContext``.

    It intentionally carries no project, principal, agent, role, grant,
    feedback-source, or owner field.  A later authorized queue adapter binds
    those facts from its trusted access argument, never from this payload.
    """

    topic: str
    run_id: RunId
    payload: TraceQueuePayload | OutcomeQueuePayload | ProposalQueuePayload
    priority: int = 100
    available_at: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.topic) is not str or self.topic not in {
            _TRACE_EVENT_TOPIC,
            _OUTCOME_EVENT_TOPIC,
            _MEMORY_PROPOSAL_TOPIC,
        }:
            raise ValueError("topic must name a supported authorized queue payload")
        if len(self.topic) > _MAX_AUTHORIZED_QUEUE_TOPIC_CHARS:  # defensive future topic bound
            raise ValueError("topic is too long")
        if type(self.run_id) is not RunId:
            raise TypeError("run_id must be a RunId")
        expected_payload_type = {
            _TRACE_EVENT_TOPIC: TraceQueuePayload,
            _OUTCOME_EVENT_TOPIC: OutcomeQueuePayload,
            _MEMORY_PROPOSAL_TOPIC: ProposalQueuePayload,
        }[self.topic]
        if type(self.payload) is not expected_payload_type:
            raise TypeError("topic and payload type must match exactly")
        if type(self.priority) is not int:
            raise TypeError("priority must be an int")
        if not _PG_INTEGER_MIN <= self.priority <= _PG_INTEGER_MAX:
            raise ValueError("priority is outside PostgreSQL integer range")
        if self.available_at is not None:
            if type(self.available_at) is not datetime:
                raise TypeError("available_at must be a datetime or None")
            if self.available_at.tzinfo is None or self.available_at.utcoffset() is None:
                raise ValueError("available_at must be timezone-aware (the column is timestamptz)")

    def to_json_payload(self) -> dict[str, object]:
        """A detached JSON-ready snapshot for a future authorized producer."""

        return self.payload.to_json_mapping()


@runtime_checkable
class PrincipalPort(Protocol):
    """Verify the caller's own credentials.

    The service always verifies its own credentials. It never trusts a host's
    asserted actor header — that assertion is exactly the thing an attacker
    would forge to cross a project wall.
    """

    def authenticate(
        self,
        *,
        authorization: str | None,
        api_key: str | None,
        deadline: RemainingBudget | None = None,
    ) -> Principal:
        """Raises `AuthenticationFailed`. Never returns an unauthenticated principal."""
        ...


@runtime_checkable
class ProjectResolverPort(Protocol):
    """principal -> project. The isolation root (invariant 4).

    Backed by the `agent_registration` table, whose `UNIQUE(principal_id)` is
    what makes the mapping a function rather than a choice.
    """

    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        """Raises `ScopeResolutionFailed` for an unregistered principal."""
        ...


@runtime_checkable
class AccessResolverPort(Protocol):
    """Resolve grants and feedback source for an already-authenticated principal.

    This is intentionally separate from the legacy project-scope resolver.
    No credential kind implies a role, and Phase 3 routes will use this port
    rather than manufacture authority from ``ProjectScope``.
    """

    def resolve_access(
        self, principal_id: PrincipalId, *, deadline: RemainingBudget | None = None
    ) -> AccessContext:
        """Raises an opaque authorization error when no active access exists."""
        ...


@runtime_checkable
class QueueProducerPort(Protocol):
    """What API routes depend on, so a route never holds a live queue implementation."""

    def enqueue(
        self,
        topic: str,
        project_id: ProjectId,
        payload: Mapping[str, object],
        priority: int = 100,
        available_at: datetime | None = None,
    ) -> int: ...


@runtime_checkable
class AuthorizedQueueProducerPort(Protocol):
    """Future Phase 3 queue surface bound to server-resolved authority.

    Kept separate from ``QueueProducerPort`` until the durable authority store
    and queue implementation land together.  Adding this method to the legacy
    producer now would falsely claim that existing ``WorkQueue`` instances
    enforce grants before they do.
    """

    def enqueue_many_authorized(
        self,
        access: AccessContext,
        writes: tuple[AuthorizedQueueWrite, ...],
    ) -> tuple[int, ...]: ...


@runtime_checkable
class QueueConsumerPort(Protocol):
    """What ingest workers depend on. Delivery is at-least-once: every consumer
    behind this port must be idempotent (trace writer on `(run_id, seq)`,
    outcome intake on `event_id`)."""

    def claim(self, topic: str, n: int) -> list[QueueItem]: ...

    def ack(self, item_id: int) -> None: ...

    def nack(self, item_id: int, backoff: timedelta) -> None: ...


@runtime_checkable
class WorkerQueueConsumerPort(Protocol):
    """The authority-v1 worker surface.

    Mutation calls receive the full claimed item so the storage adapter can
    fence the exact lease generation.  It deliberately has no enqueue method.
    """

    def claim(self, topic: str, n: int) -> list[QueueItem]: ...

    def ack(self, item: QueueItem) -> bool: ...

    def nack(self, item: QueueItem, backoff: timedelta) -> bool: ...

    def reject(self, item: QueueItem, reason: str) -> bool: ...


@runtime_checkable
class TelemetryPort(Protocol):
    """Every retrieval writes one row here — including the ones that returned nothing.

    This is what distinguishes abstention (the system working as designed) from
    a timeout (the system failing). Lift reads it, and conflating the two makes
    the kill switch measure the wrong thing.
    """

    def record_retrieval(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None: ...


@runtime_checkable
class FeedbackPort(Protocol):
    """Host events -> outcome events (Phase 3 adapters; declared now).

    Note what is absent: no weight. Invariant 8 — the server derives `w` from
    the authenticated adapter class, and a weight on the wire is rejected at the
    API with 422.
    """

    def to_outcome(self, raw: Mapping[str, object]) -> FeedbackEvent: ...


@runtime_checkable
class InvalidationPort(Protocol):
    """Platform events that make memory stale — tool changed, env fact changed,
    workflow edited (Phase 2; declared now)."""

    def poll(self) -> Sequence[Mapping[str, object]]: ...


@runtime_checkable
class LLMProviderPort(Protocol):
    """Generative inference for background workers ONLY.

    No hot-path module may reach this port. `scripts/purity_check.py` proves it
    by reachability, not by convention.
    """

    def complete(self, *, model: str, prompt: str, temperature: float, max_tokens: int) -> str: ...


@runtime_checkable
class EmbeddingPort(Protocol):
    """Query and index embedding.

    Permitted on the hot path under its own 200ms sub-budget: this is a vector
    endpoint, not a generative client. On timeout the retriever degrades to
    lexical-only rather than failing — which is nearly free now that BM25 is
    real (0.69 vs 0.70 hybrid on the audit's fixture).

    `model_id`/`model_version` are stamped on every row that gets embedded.
    Swapping either is an explicit, versioned re-embedding migration.
    """

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        """Raises `EmbeddingTimeout` past `timeout_ms`. Must not retry internally —
        the caller owns the budget."""
        ...

    @property
    def model_id(self) -> str: ...

    @property
    def model_version(self) -> str: ...


@runtime_checkable
class AuditSinkPort(Protocol):
    """Where Tracebed's own audit events go. Default: JSON-lines to stdout plus
    a Postgres audit table; an S3 sink is optional."""

    def emit(self, event: Mapping[str, object]) -> None: ...
