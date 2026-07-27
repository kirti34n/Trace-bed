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

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from tracebed.domain.enums import Arm, OutcomeCode
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
    "AuditSinkPort",
    "EmbeddingPort",
    "FeedbackPort",
    "InvalidationPort",
    "LLMProviderPort",
    "PrincipalPort",
    "ProjectResolverPort",
    "QueueConsumerPort",
    "QueueProducerPort",
    "TelemetryPort",
    "TraceStorePort",
]


@runtime_checkable
class PrincipalPort(Protocol):
    """Verify the caller's own credentials.

    The service always verifies its own credentials. It never trusts a host's
    asserted actor header — that assertion is exactly the thing an attacker
    would forge to cross a project wall.
    """

    def authenticate(self, *, authorization: str | None, api_key: str | None) -> Principal:
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
class QueueConsumerPort(Protocol):
    """What ingest workers depend on. Delivery is at-least-once: every consumer
    behind this port must be idempotent (trace writer on `(run_id, seq)`,
    outcome intake on `event_id`)."""

    def claim(self, topic: str, n: int) -> list[QueueItem]: ...

    def ack(self, item_id: int) -> None: ...

    def nack(self, item_id: int, backoff: timedelta) -> None: ...


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
