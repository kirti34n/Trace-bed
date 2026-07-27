"""Invalidation and staleness (PLAN.md §5 state machine; §7 Phase 2; §3 adapters table).

Consumes invalidation events — either drained from a live `adapters.ports.InvalidationPort`
(`adapters/invalidation.py`'s two shipped defaults) or read back from a persisted
`invalidation_event` row (D-041) — resolves the PROVENANCE SELECTOR each event carries
(`provenance.tool_refs` / `trace_ids` / `input_sig_hashes`) against every memory that
derives from the changed thing, and transitions their dependents `validated -> stale`
through `domain.state_machine.apply()`. The `cache_flush` event type (D-041 /
`stores.valkey.flush`) is handled separately: it flushes a project's Valkey namespace and
touches no `memory_item` row at all.

CONTRACT GAP (reported, not deviated on): `stores.pg.repo.Repo` already has an indexed
status-predicate query (`Repo.list_memories(project_id, statuses=[...])`, satisfying most of
`select_by_status` structurally), but it has no method that resolves memories by provenance
selector and no write path for a `memory_item` status/strike/q_value change — neither is in
`stores/pg/repo.py`, which is outside this chunk's file list (hard rule 6). It also returns
`stores.pg.rows.MemoryItemRow`, which does not carry `last_retrieved_at` /
`last_revalidated_at` even though both columns exist in `migrations/0002_partitioned.sql` —
a real `select_by_status`/`select_due_for_revalidation` is a thin adapter over
`Repo.list_memories` plus those two columns, not a new query shape. This module defines
`MemoryLifecycleRepoPort` as exactly what it, `workers/revalidation.py`, and
`workers/sweeps.py` need; a `Repo`-backed implementation (and the small `MemoryItemRow`/
`Repo.list_memories` extension it needs) is the natural next step for whoever owns
`stores/pg/repo.py` next. The offline test suite (`tests/phase2/`) substitutes an in-memory
fake carrying the identical shape, so every transition here is exercised against real
`domain.state_machine.apply()` logic today, with zero database.

Hard rule 5 is enforced structurally: nowhere in this file (or `revalidation.py` /
`sweeps.py`) does a `Status` get written that did not come straight out of an `apply()`
call, except the one reflexive case documented on `MemoryLifecycleRepoPort.persist` — a
plain field touch where `from_status == to_status`, i.e. nothing changed, so there is
nothing for the state machine to authorise. Every `apply()` call in the three modules
passes the row's OWN `status` as `current`, never a literal the call site assumed: a
hard-coded `current` makes the machine judge an edge the row may not be on, which is a
status change that did not really go through the state machine no matter how it reads.

`process_event` also RE-ASSERTS the store's provenance-selector resolution on every row it
gets back, before the first write. Over-invalidation is a vault-wide availability
primitive — one selector that over-matches demotes every validated memory in a project out
of `RETRIEVABLE_STATUSES` in a single event — and `select_by_provenance` has no
implementation yet, so the predicate that is supposed to stop that does not exist to be
trusted.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.stores.valkey.flush import CACHE_FLUSH_EVENT_TYPE

__all__ = [
    "InvalidationEvent",
    "InvalidationSelector",
    "Invalidator",
    "InvalidatorResult",
    "LifecycleMemoryRow",
    "LifecycleTransitionWrite",
    "MemoryLifecycleRepoPort",
    "parse_invalidation_payload",
    "require_aware",
    "selector_matches",
]


def require_aware(name: str, value: datetime | None) -> datetime | None:
    """Refuse a timezone-naive datetime, mirroring `TransitionEvidence.__post_init__`.

    Every timestamp these workers subtract (`now - last_retrieved_at`, `now - created_at`)
    is one a naive value silently skews or loudly crashes: two naive values compare
    successfully but shift every TTL and idle window by the deployment's UTC offset, and
    one naive against the `Clock`'s aware `now` raises a bare `TypeError` out of a sweep.
    `state_machine` already refuses this for the two fields it sees; the two idle-reference
    columns never reach it, so the refusal has to live where they are first read.
    """
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{name} must be timezone-aware; got a naive datetime")
    return value


# --------------------------------------------------------------------------- #
# Shared shapes — imported by revalidation.py and sweeps.py too, so all three
# Phase 2 lifecycle workers agree on one read/write model instead of three.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LifecycleMemoryRow:
    """The projection of a `memory_item` row these Phase 2 lifecycle workers need.

    Deliberately smaller than `stores.pg.rows.MemoryItemRow`: no `content` (these workers
    never render or reason about memory text, only its governance metadata), and it adds
    `last_retrieved_at` — a real DDL column (migrations/0002_partitioned.sql) that
    `MemoryItemRow` does not expose yet (contract_gap, reported above).
    """

    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    provenance: Provenance
    status_changed_at: datetime | None
    strike_count: int
    last_retrieved_at: datetime | None
    created_at: datetime
    q_value: float = 0.5
    """The row's live `memory_item.q_value`. Read by `sweeps.decay_sweep` so a decay pass
    that would not lower it writes nothing at all — without it the sweep cannot tell a
    no-op from a real decay step and re-writes every idle row on every run."""

    def __post_init__(self) -> None:
        for name in ("status_changed_at", "last_retrieved_at", "created_at"):
            require_aware(f"LifecycleMemoryRow.{name}", getattr(self, name))
        if not 0.0 <= self.q_value <= 1.0:
            raise ValueError(
                f"LifecycleMemoryRow.q_value={self.q_value} is outside [0.0, 1.0]; "
                f"memory_item.q_value is a clamped probability (migrations/0002)"
            )


@dataclass(frozen=True, slots=True)
class LifecycleTransitionWrite:
    """One committed write, handed to `MemoryLifecycleRepoPort.persist`.

    `to_status` is always whatever `state_machine.apply()` returned for this row — never a
    value this module invents — except when `from_status == to_status`, which names a plain
    field touch with no status change at all (see `MemoryLifecycleRepoPort.persist`).
    """

    memory_id: MemoryId
    from_status: Status
    to_status: Status
    now: datetime
    strike_count: int | None = None
    q_value: float | None = None
    last_revalidated_at: datetime | None = None


@runtime_checkable
class MemoryLifecycleRepoPort(Protocol):
    """What `invalidator` / `revalidation` / `sweeps` need from a memory store.

    `select_by_status` MUST be an indexed `(project_id, status)` query — Phase 2's gate
    clause "sweep cost scales with vault size, not trace volume" depends on it never
    touching anything but `memory_item`.
    """

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        """Every row whose provenance overlaps ANY of the three given selector fields
        (union, not intersection — a tool-changed event and a trace-level selector are
        different evidence classes and either alone is grounds to re-examine a memory)."""
        ...

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        """Indexed on `(project_id, status)`. Never reads `trace_index` or any trace-store
        object — this is what makes a sweep's cost a function of matching `memory_item`
        rows alone."""
        ...

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        """`validated` rows whose idle reference (`last_retrieved_at`, or `created_at` if
        never retrieved) is at or before `older_than`. Indexed the same way as
        `select_by_status`."""
        ...

    def persist(self, project_id: ProjectId, write: LifecycleTransitionWrite) -> None:
        """Writes exactly the fields present on `write`.

        When `write.from_status == write.to_status` this is a plain field touch with NO
        state-machine involvement, because nothing about the row's status changed —
        reachable only from `revalidation.RevalidationWorker.check_validated`'s passing
        branch and `sweeps.decay_sweep`'s not-yet-at-floor branch. Every other call site in
        these three modules sets `to_status` to exactly what `state_machine.apply()` just
        returned; this method must never be used to invent a status this module did not get
        from `apply()`.
        """
        ...


# --------------------------------------------------------------------------- #
# Invalidation events — the raw payload shape shared with adapters/invalidation.py
# and Repo.insert_invalidation_event's (event_type, selector) columns (D-041).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class InvalidationSelector:
    """PLAN.md §7: "resolves PROVENANCE SELECTORS ... via provenance.tool_refs / trace_ids /
    input_sig_hashes"."""

    tool_refs: tuple[str, ...] = ()
    trace_ids: tuple[RunId, ...] = ()
    input_sig_hashes: tuple[bytes, ...] = ()

    def is_empty(self) -> bool:
        return not (self.tool_refs or self.trace_ids or self.input_sig_hashes)


def selector_matches(provenance: Provenance, selector: InvalidationSelector) -> bool:
    """Whether `provenance` names at least one of the things `selector` points at.

    THE definition of "depends on the changed thing", and deliberately structural: it reads
    `provenance.tool_refs` / `trace_ids` / `input_sig_hashes` and nothing else. A memory
    whose CONTENT merely mentions a tool id shares no provenance entry with it and is
    therefore not a dependent — "flip a tool definition and only its dependents go stale"
    is this function, not a store's `LIKE`.
    """
    return bool(
        (set(selector.tool_refs) & set(provenance.tool_refs))
        or (set(selector.trace_ids) & set(provenance.trace_ids))
        or (set(selector.input_sig_hashes) & set(provenance.input_sig_hashes))
    )


@dataclass(frozen=True, slots=True)
class InvalidationEvent:
    event_type: str
    selector: InvalidationSelector
    fired_at: datetime | None = None
    """When the SOURCE says this happened. Deliberately not used as the evidence timestamp
    in `Invalidator.process_event` — every transition's `now` comes from the injected
    `Clock` (hard rule 3), never from caller/source-supplied wall-clock data."""


def parse_invalidation_payload(raw: Mapping[str, object]) -> InvalidationEvent:
    """Turns one raw `{"event_type": ..., "selector": {...}}` payload — the shape both
    `adapters.invalidation`'s two sources and `Repo.insert_invalidation_event`'s persisted
    `selector` column use — into a typed `InvalidationEvent`.

    Raises `ValueError` on a malformed payload. Deliberately not a `TracebedError` subclass:
    `domain/errors.py` is outside this chunk's file list (hard rule 6) and has no member
    named for "malformed invalidation payload" — reported as a contract_gap for whoever
    next touches that file, rather than silently reusing an unrelated exception class.
    """
    event_type = raw.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        raise ValueError(f"invalidation payload missing a string 'event_type': {raw!r}")

    raw_selector = raw.get("selector") or {}
    if not isinstance(raw_selector, Mapping):
        raise ValueError(f"invalidation payload 'selector' must be a mapping: {raw!r}")

    tool_refs = tuple(str(t) for t in _as_seq(raw_selector.get("tool_refs")))
    trace_ids = tuple(RunId(str(t)) for t in _as_seq(raw_selector.get("trace_ids")))
    input_sig_hashes = tuple(
        bytes.fromhex(str(h)) for h in _as_seq(raw_selector.get("input_sig_hashes"))
    )

    fired_at_raw = raw.get("fired_at")
    # D-043's rule applied at this wire boundary: a naive `fired_at` is refused where it
    # arrives, not carried as a trap for the first consumer that subtracts it. The column is
    # `timestamptz`, so Postgres would reinterpret a naive value in the session TimeZone.
    fired_at = (
        require_aware("fired_at", datetime.fromisoformat(str(fired_at_raw)))
        if fired_at_raw is not None
        else None
    )

    return InvalidationEvent(
        event_type=event_type,
        selector=InvalidationSelector(
            tool_refs=tool_refs, trace_ids=trace_ids, input_sig_hashes=input_sig_hashes
        ),
        fired_at=fired_at,
    )


def _as_seq(value: object) -> Sequence[object]:
    """A JSON array, and nothing that merely behaves like one.

    `str`, `bytes` and `bytearray` are all `Sequence`s whose elements are characters/ints,
    so `{"tool_refs": "tool-x"}` would silently become the six selectors `("t","o","o",...)`
    and `b"ab"` the two selectors `("97","98")` — a malformed payload resolving to a
    *different, wrong* selector rather than being refused.
    """
    if value is None:
        return ()
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValueError(f"expected a list, got {type(value).__name__}: {value!r}")
    return value


# --------------------------------------------------------------------------- #
# The worker.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class InvalidatorResult:
    event_type: str
    cache_flushed: bool
    flushed_keys: int
    considered: tuple[MemoryId, ...]
    """Every candidate row a provenance selector match returned, whether or not it was
    eligible to transition — this is what the "nothing else does" half of the gate test
    checks against (over-invalidation is as bad as under-invalidation)."""
    transitioned_to_stale: tuple[MemoryId, ...]


class Invalidator:
    """PLAN.md §7 Phase 2: "consumes invalidation events, resolves provenance selectors
    ... and transitions their dependents validated -> stale ... Also handles the
    cache_flush event type against stores/valkey/flush.py."

    CONTRACT GAP: no queue topic or scheduled loop currently wires a live
    `adapters.ports.InvalidationPort` (or persisted `invalidation_event` rows) into a call
    here — `stores/pg/queue.py` (D-041) explicitly has no fourth topic for this, and
    `ingest/`/`api/` are outside this chunk's file list. `process_event`/`process_raw_batch`
    are this chunk's real, tested behaviour; wiring a periodic drain into a call to one of
    them is reported as remaining work for whoever owns that seam next.
    """

    def __init__(
        self,
        repo: MemoryLifecycleRepoPort,
        clock: Clock,
        *,
        flush_cache: Callable[[ProjectId], int] | None = None,
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._flush_cache = flush_cache

    def process_event(
        self, project_id: ProjectId, event: InvalidationEvent, cfg: EffectiveConfig
    ) -> InvalidatorResult:
        if event.event_type == CACHE_FLUSH_EVENT_TYPE:
            # `cache_flushed` reports whether a flush ACTUALLY happened, not whether one was
            # requested. A deployment wired without `flush_cache` previously reported every
            # cache_flush as flushed while the tool cache kept serving the results the event
            # existed to discard — a silent failure on the one path whose whole job is to
            # stop stale, possibly confused-deputy, cached tool output being reused.
            if self._flush_cache is None:
                return InvalidatorResult(
                    event_type=event.event_type,
                    cache_flushed=False,
                    flushed_keys=0,
                    considered=(),
                    transitioned_to_stale=(),
                )
            return InvalidatorResult(
                event_type=event.event_type,
                cache_flushed=True,
                flushed_keys=self._flush_cache(project_id),
                considered=(),
                transitioned_to_stale=(),
            )

        if event.selector.is_empty():
            return InvalidatorResult(
                event_type=event.event_type,
                cache_flushed=False,
                flushed_keys=0,
                considered=(),
                transitioned_to_stale=(),
            )

        candidates = self._repo.select_by_provenance(
            project_id,
            tool_refs=event.selector.tool_refs,
            trace_ids=event.selector.trace_ids,
            input_sig_hashes=event.selector.input_sig_hashes,
        )
        # The store resolves the selector; this module RE-ASSERTS the result before acting on
        # it, and does so before the first write so a breached post-condition can never leave
        # a half-invalidated vault behind. `select_by_provenance` has no implementation yet
        # (contract gap, module docstring) and every alternative one — a hand-written variant,
        # a `LIKE` over content, a cache in front of the query, a driver for a different store
        # — reaches this loop while bypassing whatever predicate the eventual SQL contains.
        # Over-invalidation is a vault-wide availability primitive: one broad selector that
        # over-matches demotes every validated memory in a project to `stale`, i.e. out of
        # `RETRIEVABLE_STATUSES`, in a single event. Failing closed costs one invalidation
        # (the changed thing's dependents stay validated until the R-day revalidation sweep
        # re-checks them); failing open costs the whole vault.
        for row in candidates:
            if row.project_id != project_id:
                raise TracebedError(
                    f"select_by_provenance returned memory {row.id} scoped to project "
                    f"{row.project_id}, not the requested {project_id} (invariant 4)"
                )
            if not selector_matches(row.provenance, event.selector):
                raise TracebedError(
                    f"select_by_provenance returned memory {row.id}, whose provenance shares "
                    f"no tool_ref, trace_id or input_sig_hash with the event selector; "
                    f"invalidation must not reach beyond a changed thing's real dependents"
                )

        limits = TransitionLimits.from_config(cfg)
        now = self._clock.now()

        considered: list[MemoryId] = []
        transitioned: list[MemoryId] = []
        for row in candidates:
            considered.append(row.id)
            if row.status is not Status.VALIDATED:
                # Only a validated row can go stale (PLAN.md §5 row 10). Everything else a
                # selector happens to match (quarantined, candidate, already-stale, ...) is
                # considered but deliberately left untouched — over-invalidation is as bad
                # as under-invalidation.
                continue
            evidence = TransitionEvidence(
                now=now,
                provenance_class=row.provenance.cls,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                status_changed_at=row.status_changed_at,
                invalidation_event=True,
            )
            # `row.status`, never the literal `Status.VALIDATED`: the machine must judge the
            # edge the row is actually on. A hard-coded `current` turns `apply()` into a
            # rubber stamp for whatever the store handed back — the guard passes on the
            # evidence while the row underneath is on an edge PLAN.md §5 does not contain.
            new_status = apply(row.status, Status.STALE, evidence, limits)
            self._repo.persist(
                project_id,
                LifecycleTransitionWrite(
                    memory_id=row.id,
                    from_status=row.status,
                    to_status=new_status,
                    now=now,
                    # PLAN.md §5 row 10 lumps invalidation/TTL-class/revalidation-fail under
                    # one "(strike 1)" annotation: whichever route puts a row into `stale`
                    # writes strike_count=1, so `stale -> retired`'s guard (strike_count>=2,
                    # workers.revalidation) is reachable by exactly one more failure, never
                    # by a row that started at strike_count=0.
                    strike_count=1,
                ),
            )
            transitioned.append(row.id)

        return InvalidatorResult(
            event_type=event.event_type,
            cache_flushed=False,
            flushed_keys=0,
            considered=tuple(considered),
            transitioned_to_stale=tuple(transitioned),
        )

    def process_raw_batch(
        self,
        project_id: ProjectId,
        raw_events: Sequence[Mapping[str, object]],
        cfg: EffectiveConfig,
    ) -> tuple[InvalidatorResult, ...]:
        """Convenience for draining an `adapters.ports.InvalidationPort.poll()` result (or
        any sequence of raw `{"event_type", "selector"}` payloads) in one call.

        Every payload is parsed BEFORE any of them is processed, so a malformed payload
        anywhere in the batch refuses the batch with nothing written. Parsing lazily inside
        the loop meant the events before the bad one had already transitioned memories to
        `stale` when the `ValueError` propagated — and the caller, holding only the
        exception, had no record of which ones.
        """
        parsed = [parse_invalidation_payload(raw) for raw in raw_events]
        return tuple(self.process_event(project_id, event, cfg) for event in parsed)
