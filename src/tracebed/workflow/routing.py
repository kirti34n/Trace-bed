"""Routing records: run-shape evidence for an external orchestrator (PLAN.md §7 Phase 4).

Tracebed records that "runs shaped like this went to agent X and it went well/badly";
it does not route. `record_routing_outcome` appends one immutable fact.
`routing_evidence_for` hands back a tuple of `RoutingEvidence` — raw historical facts
plus, where available, an embedding-similarity number — and NOTHING ELSE: no score
field, no rank, no `recommended_agent`. An orchestrator reads the evidence and decides;
that decision never happens inside this module. Keeping that boundary sharp in the API
shape (rather than as a comment nobody reads) is this chunk's explicit task.

SIGNATURE SCHEME: reused, not reinvented. "Shaped like this" is exactly
`domain.signatures.input_signature_hash` — the same 40-byte
(32-byte structural sha256 || 8-byte free-text SimHash) signature that backs shadow-
confirmation independence (D-020, invariant 7). `same_signature_shape` below is the one
match predicate every `RoutingRecordStore` backend must implement identically: exact
equality on the structural half (agent_type + workflow_template + sorted tool_manifest)
and `domain.signatures.same_cluster` (Hamming <= `SAME_CLUSTER_MAX_HAMMING`) on the
free-text half. There is exactly one signature scheme in this codebase; this module
does not add a second one.

FREE-TEXT-HEAD EMBEDDING: a `RoutingRecord` may additionally carry the embedding vector
of its free-text head (computed upstream by whatever already calls `EmbeddingPort` —
this module never performs an embedding call itself, so it has no generative or vector
dependency at all). Where both a query and a candidate record carry one,
`routing_evidence_for` attaches their cosine similarity to the evidence entry as a
second, independent signal alongside the SimHash-cluster match — an orchestrator wanting
finer-grained "how similar, exactly" than an 8-bit Hamming bucket can read it; it is
never used to filter or rank the results this module returns.

STORAGE (contract gap, reported rather than silently improvised): PLAN.md §5's DDL
sketch defines no `routing_record` table, and this chunk's file list is
`workflow/routing.py` + `workflow/prefetch.py` only (rule 7) — it does not own
`stores/pg` or `migrations/`. `RoutingRecordStore` is therefore a Protocol seam, and
`InMemoryRoutingRecordStore` is the reference implementation this module ships and the
one every test in `tests/phase4/test_routing.py` runs against. A durable Postgres-backed
`RoutingRecordStore` (partitioned by `project_id` like every other learning-plane table,
per invariant 4) is unbuilt; whoever owns `stores/pg` next needs a `routing_record`
table added to PLAN.md §5 and a migration before one can exist. The Protocol boundary is
exactly where that backend plugs in with zero change to this module — but do not read
`InMemoryRoutingRecordStore` as more than it is: it is process-local, unbounded (nothing
evicts, nothing expires), and empty after a restart. It is a correct reference and test
double, NOT a production cache tier.

ISOLATION IS CHECKED TWICE, on purpose. `for_signature` takes the `ProjectId` and must
filter on it, and `routing_evidence_for` re-checks `record.project_id` against the scope
before returning anything. `RoutingRecordStore` is an open Protocol, so "every future
implementation gets its WHERE clause right" is not something this module can assume any
more than the typed repository assumes it and skips RLS (invariant 4).
"""

from __future__ import annotations

import math
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol, get_args, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.ids import PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.signatures import SIG_HASH_LEN, input_signature_hash, same_cluster

__all__ = [
    "InMemoryRoutingRecordStore",
    "RoutingEvidence",
    "RoutingOutcome",
    "RoutingRecord",
    "RoutingRecordStore",
    "record_routing_outcome",
    "routing_evidence_for",
    "same_signature_shape",
]

# Mirrors `domain.events.FeedbackEvent.outcome`'s wire vocabulary (D-032's "went well/
# badly" is exactly this pair) rather than inventing a third spelling of the same idea.
RoutingOutcome = Literal["positive", "negative"]

ROUTING_OUTCOMES: Final[frozenset[str]] = frozenset(get_args(RoutingOutcome))
"""The `RoutingOutcome` vocabulary as runtime data, derived from the type rather than
retyped beside it. `outcome` reaches `record_routing_outcome` from an orchestrator's
request body, where a `Literal` annotation is a promise the wire cannot keep — the same
reason `domain.signatures._normalise_tool_manifest` validates a `Sequence[str]` that
static typing already "guarantees". An unchecked third value would be stored, returned as
evidence, and counted by whatever an orchestrator groups on."""


@dataclass(frozen=True, slots=True)
class RoutingRecord:
    """One immutable fact: a run shaped like `input_signature` was routed to
    `routed_to`, and the outcome was `outcome`. Never mutated after append — routing
    evidence is a log, not a rolling average, so a later bad outcome cannot quietly
    overwrite an earlier good one (the same reasoning D-011 applies to Q, applied here
    to raw history instead of a derived score).

    `run_id` and `principal_id` are the provenance half of "evidence, not a
    recommendation": every entry `routing_evidence_for` returns traces back to the exact
    run and authenticated principal that produced it, so an orchestrator (or a human
    auditing a bad routing decision later) can always ask "what actually happened on
    that run" instead of trusting a bare assertion.
    """

    project_id: ProjectId
    principal_id: PrincipalId
    run_id: RunId
    routed_to: str
    outcome: RoutingOutcome
    input_signature: bytes
    free_text_embedding: tuple[float, ...] | None
    recorded_at_ms: int

    def __post_init__(self) -> None:
        if len(self.input_signature) != SIG_HASH_LEN:
            raise ValueError(
                f"RoutingRecord.input_signature must be {SIG_HASH_LEN} bytes, "
                f"got {len(self.input_signature)}"
            )
        if not self.routed_to:
            raise ValueError("RoutingRecord.routed_to must not be empty")
        if self.outcome not in ROUTING_OUTCOMES:
            raise ValueError(
                f"RoutingRecord.outcome must be one of {sorted(ROUTING_OUTCOMES)}, "
                f"got {self.outcome!r}"
            )
        if self.free_text_embedding is None:
            return
        if not self.free_text_embedding:
            raise ValueError("RoutingRecord.free_text_embedding must not be empty when present")
        # NaN/inf are rejected at the boundary rather than handled downstream: a NaN
        # component makes `_cosine` return NaN, which is not `None` and so reads as a
        # measured similarity, while comparing false against every threshold an
        # orchestrator applies to it. `domain.canonical.canonical_json` refuses the same
        # values for the same reason (C-01, `allow_nan=False`).
        if not all(math.isfinite(component) for component in self.free_text_embedding):
            raise ValueError(
                "RoutingRecord.free_text_embedding must contain only finite values"
            )


def same_signature_shape(a: bytes, b: bytes) -> bool:
    """"Shaped like this", precisely (PLAN.md §7 Phase 4): identical structural features
    — the leading 32 sha256 bytes of `domain.signatures.input_signature_hash`, i.e. the
    same `agent_type`, `workflow_template`, and sorted `tool_manifest` — AND the same
    free-text SimHash cluster (`domain.signatures.same_cluster` on the trailing 8 bytes).
    Exact structural equality alone would treat "same tools, wildly different request"
    as one shape; cluster membership alone would treat two unrelated agent types that
    happen to phrase a query identically as one shape. Both together is what
    `RoutingRecordStore.for_signature` and `routing_evidence_for` match on, and it is the
    ONLY match predicate in this module — a second, looser one would silently become a
    second signature scheme.
    """
    if len(a) != SIG_HASH_LEN or len(b) != SIG_HASH_LEN:
        raise ValueError(f"same_signature_shape: expected {SIG_HASH_LEN}-byte signatures")
    return a[:32] == b[:32] and same_cluster(a, b)


def _cosine(a: tuple[float, ...] | None, b: tuple[float, ...] | None) -> float | None:
    """Cosine similarity, or `None` when either side has no embedding, the two have
    mismatched dimensionality (a stale record from a since-repinned embedding model —
    D-007's re-embedding migration changes dimension), or either vector is the zero
    vector (cosine is undefined there, not zero). `None` is a distinct, honest "no
    signal" answer — inventing 0.0 for any of these would read as "measured and found
    dissimilar", which is not what happened.
    """
    if a is None or b is None or len(a) != len(b) or not a:
        return None
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return None
    return dot / (norm_a * norm_b)


def _validated_embedding(values: Sequence[float] | None) -> tuple[float, ...] | None:
    """The query side of the same rule `RoutingRecord.__post_init__` applies to the
    stored side: no empty vector, no NaN/inf. Both sides feed `_cosine`, so validating
    only the stored one would leave the caller's vector able to produce a NaN
    "similarity" — a fabricated number wearing the shape of a measurement.
    """
    if values is None:
        return None
    vector = tuple(values)
    if not vector:
        raise ValueError("free_text_embedding must not be empty when present")
    if not all(math.isfinite(component) for component in vector):
        raise ValueError("free_text_embedding must contain only finite values")
    return vector


@dataclass(frozen=True, slots=True)
class RoutingEvidence:
    """What `routing_evidence_for` returns: one matching historical fact, plus the
    embedding-similarity number when computable. THIS IS DATA, DELIBERATELY MINIMAL —
    there is no `score`, `rank`, or `recommended_agent` field here and there never will
    be one on this type; a field like that would turn "evidence" into "a
    recommendation" by shape alone, regardless of what the docstring says. An
    orchestrator that wants a ranked decision combines `record.outcome`,
    `record.recorded_at_ms` (recency), and `embedding_similarity` on its own, outside
    Tracebed.
    """

    record: RoutingRecord
    embedding_similarity: float | None


@runtime_checkable
class RoutingRecordStore(Protocol):
    """Storage seam for `RoutingRecord`s (see the module docstring's contract-gap note:
    no Postgres-backed implementation ships in this chunk). `for_signature` MUST return
    only records for which `same_signature_shape(record.input_signature, input_signature)`
    is true — that predicate is defined once, in this module, precisely so every backend
    (the in-memory reference here, and any future Postgres-backed one) matches
    identically rather than each inventing its own notion of "similar enough".
    """

    def append(self, record: RoutingRecord) -> None:
        """Append one immutable record. Never a partial update, never an upsert —
        routing evidence is written once, at the end of the run it describes."""
        ...

    def for_signature(
        self, project_id: ProjectId, input_signature: bytes
    ) -> Sequence[RoutingRecord]:
        """Every record for `project_id` whose shape matches `input_signature`
        (`same_signature_shape`), and nothing from any other project — the wall is a
        construction-time discipline in every store, not only the Postgres-backed
        ones (invariant 4)."""
        ...


class InMemoryRoutingRecordStore:
    """Reference `RoutingRecordStore` (see the module docstring). Keyed by `project_id`
    even in memory: `for_signature` only ever reads its own project's list, so a test
    exercising two projects through this store exercises the same isolation discipline a
    real backend must hold, not merely "happens not to leak" for lack of a second
    project's data to leak.

    Guarded by one lock, because Phase 4 is the phase with genuinely concurrent callers:
    an orchestrator running parallel branches writes routing records from several threads
    while others read evidence. `list.append` being individually atomic under CPython's
    GIL is not the guarantee needed here — `for_signature` must see a stable list while it
    filters (and must not depend on a GIL that a free-threaded build removes), and it
    returns a snapshot tuple so a caller iterating evidence is never racing a writer.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_project: dict[ProjectId, list[RoutingRecord]] = {}

    def append(self, record: RoutingRecord) -> None:
        with self._lock:
            self._by_project.setdefault(record.project_id, []).append(record)

    def for_signature(
        self, project_id: ProjectId, input_signature: bytes
    ) -> Sequence[RoutingRecord]:
        with self._lock:
            records = tuple(self._by_project.get(project_id, ()))
        return tuple(
            r for r in records if same_signature_shape(r.input_signature, input_signature)
        )


def record_routing_outcome(
    store: RoutingRecordStore,
    scope: ProjectScope,
    *,
    run_id: RunId,
    query_text: str,
    workflow_template: str | None,
    tool_manifest: Sequence[str] | None,
    routed_to: str,
    outcome: RoutingOutcome,
    free_text_embedding: Sequence[float] | None,
    clock: Clock,
) -> RoutingRecord:
    """Compute the input signature via `domain.signatures.input_signature_hash` — the
    one signature scheme this module reuses rather than reinventing — and append one
    immutable `RoutingRecord`. `scope.project_id`/`scope.agent_type_id`/
    `scope.principal_id` are the server-resolved triple (invariant 4: never a
    caller-asserted project or agent type), matching every other write path in this
    codebase.
    """
    signature = input_signature_hash(
        agent_type_id=scope.agent_type_id,
        query_text=query_text,
        workflow_template=workflow_template,
        tool_manifest=tool_manifest,
    )
    record = RoutingRecord(
        project_id=scope.project_id,
        principal_id=scope.principal_id,
        run_id=run_id,
        routed_to=routed_to,
        outcome=outcome,
        input_signature=signature,
        free_text_embedding=_validated_embedding(free_text_embedding),
        recorded_at_ms=clock.now_ms(),
    )
    store.append(record)
    return record


def routing_evidence_for(
    store: RoutingRecordStore,
    scope: ProjectScope,
    *,
    query_text: str,
    workflow_template: str | None,
    tool_manifest: Sequence[str] | None,
    free_text_embedding: Sequence[float] | None = None,
) -> tuple[RoutingEvidence, ...]:
    """Evidence for "runs shaped like this one", never a decision (PLAN.md §7 Phase 4:
    "An orchestrator may read the record and decide"). Matches via
    `same_signature_shape` on the same 40-byte signature every other corroboration check
    in this codebase uses (D-020) — a `query_text`/`workflow_template`/`tool_manifest`
    combination this near-identical to a past run's is "shaped like this one"; nothing
    coarser or fuzzier is used.

    The result is re-filtered here (not merely trusted from `store.for_signature`) on
    BOTH axes before being wrapped:

    * `record.project_id == scope.project_id` — invariant 4 is enforced at the point a
      row is used, in every store, and a `RoutingRecordStore` is a store. `for_signature`
      already takes the project id, so this check is redundant against a correct backend
      and is exactly the point: the wall must not depend on every future implementation
      of a Protocol getting its WHERE clause right, any more than Postgres isolation
      depends on the repository alone (RLS is the same argument in the same codebase).
    * `same_signature_shape(...)` — a backend that got the match predicate wrong must not
      be able to fabricate evidence for an unrelated run shape just because it satisfies
      the Protocol's method names.
    """
    query_signature = input_signature_hash(
        agent_type_id=scope.agent_type_id,
        query_text=query_text,
        workflow_template=workflow_template,
        tool_manifest=tool_manifest,
    )
    query_embedding = _validated_embedding(free_text_embedding)
    candidates = store.for_signature(scope.project_id, query_signature)
    return tuple(
        RoutingEvidence(
            record=record,
            embedding_similarity=_cosine(query_embedding, record.free_text_embedding),
        )
        for record in candidates
        if record.project_id == scope.project_id
        and same_signature_shape(record.input_signature, query_signature)
    )
